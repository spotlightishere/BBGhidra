package space.joscomputing.BBGhidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import space.joscomputing.BBGhidra.formats.BootInfoMetadata;
import space.joscomputing.BBGhidra.formats.MappedLZMAReader;
import space.joscomputing.BBGhidra.formats.MappedSection;
import space.joscomputing.BBGhidra.formats.SFIHeader;
import space.joscomputing.BBGhidra.helpers.MemoryHelper;
import space.joscomputing.BBGhidra.helpers.SFIImageType;
import space.joscomputing.BBGhidra.helpers.SegmentInfo;

public class SFILoader extends AbstractProgramWrapperLoader {
    @Override
    public String getName() {
        return "BlackBerry Signed File Image";
    }

    /** Determines the type of image via metadata in file system. */
    private SFIImageType determineImageType(ByteProvider provider) throws IOException {
        // The following is adapted from discussion over getting FileAttributes from the underlying FS:
        // https://github.com/NationalSecurityAgency/ghidra/discussions/7355#discussioncomment-11803754.
        //
        // We want to make certain that we're loading from our custom file system.
        String filesystemType = provider.getFSRL().getFS().getProtocol();
        if (!filesystemType.equals(SFIFileSystem.FS_TYPE)) {
            // This is not our file system.
            return null;
        }

        // We then look up our file within our custom file system to obtain its attributes.
        try (RefdFile rf = FileSystemService.getInstance().getRefdFile(provider.getFSRL(), null)) {
            GFileSystem currentFs = rf.fsRef.getFilesystem();

            // Attempt to get the exact SFIImageType from FS-specific attributes.
            // Note that this may be null.
            return currentFs
                    .getFileAttributes(rf.file, null)
                    .get(FileAttributeType.UNKNOWN_ATTRIBUTE, SFIImageType.class, null);
        } catch (CancelledException e) {
            // We have no need to rethrow CancelledException.
            return null;
        }
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // First, attempt to determine this image's type via the underlying file system.
        SFIImageType imageType = determineImageType(provider);
        if (imageType == null) {
            // We can't handle loading this file.
            return loadSpecs;
        }

        // Otherwise, we can determine what language to load.
        String languageId = imageType.getLanguageId();
        loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(languageId, "default"), true));
        return loadSpecs;
    }

    @Override
    protected void load(Program program, ImporterSettings settings) throws IOException {
        try (ByteProvider provider = settings.provider()) {
            loadForReal(provider, program, settings);
        } catch (IOException | AddressOverflowException | LockException e) {
            throw new LoadException(e);
        }
    }

    private void loadForReal(ByteProvider provider, Program program, ImporterSettings settings)
            throws IOException, AddressOverflowException, LockException {
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        MemoryHelper helper = new MemoryHelper(program, settings);

        // First, attempt to determine this image's type via the underlying file system.
        SFIImageType imageType = determineImageType(provider);
        if (imageType == null) {
            // We can't handle loading this file.
            throw new IOException("Unknown image type being loaded");
        }

        long compressedOffset = 0;
        long compressedSize = 0;

        if (imageType == SFIImageType.MODEM) {
            // Our underlying provider contains our full contents.
            compressedSize = provider.length();
        } else if (imageType == SFIImageType.APP) {
            // If this is an app image, we need to first import
            // the BlackBerry OS and app image.
            //
            // Please note that the BlackBerry app image exists outside
            // the Qualcomm app image, which is within the compressed LZMA data.
            //
            // Our contents skip over the actual SFI format header,
            // so we begin at offset zero.
            SFIHeader header = new SFIHeader(provider, 0L);

            // First, import OS as-is.
            // OS will always be our base address.
            SegmentInfo osInfo = header.getOsSegmentInfo();
            Address osBaseAddress = addressSpace.getAddress(osInfo.blockAddress());
            program.setImageBase(osBaseAddress, true);

            InputStream osImage = provider.getInputStream(header.getOsImageOffset());
            helper.createInitializedBlock(header.getOsSegmentInfo(), osImage);

            // Next, import app as-is.
            InputStream appImage = provider.getInputStream(header.getAppImageOffset());
            helper.createInitializedBlock(header.getAppSegmentInfo(), appImage);

            // Finally, forward the L4 offset and size metadata.
            compressedOffset = header.getL4Offset() - SFIHeader.SFI_HEADER_LENGTH;
            compressedSize = header.getL4Size();
        }

        // Parse and unpack our LZMA-compressed segments.
        MappedLZMAReader compressedMapping = new MappedLZMAReader(provider, compressedOffset, compressedSize);
        compressedMapping.readMapping();

        // TODO: Probably create uninitialized blocks,
        // but boot info might also match?
        //
        // The last segment in our LZMA-compressed segments is okL4's BootInfo.
        // We parse this to obtain segment names and other mappings (e.g. heap).
        MappedSection lastSection = compressedMapping.getSections().getLast();
        BootInfoMetadata metadata = new BootInfoMetadata(lastSection.decompress());
        HashMap<Long, SegmentInfo> metadataSegments = metadata.parseEntries();

        // For all compressed sections, get the corresponding segment metadata.
        for (MappedSection section : compressedMapping.getSections()) {
            long baseAddress = section.getCompressedBaseAddress();
            SegmentInfo current = metadataSegments.get(baseAddress);

            String segmentName;
            if (current == null) {
                // TODO: Something is awry here. We shouldn't be here.
                // However, we'll work around it for now.
                // throw new IOException("Section loading to segment without metadata!");

                segmentName = String.format("NO_METADATA_%x", baseAddress);
            } else {
                segmentName = current.segmentName();
            }

            byte[] decompressed = section.decompress();
            SegmentInfo modified = new SegmentInfo(baseAddress, decompressed.length, segmentName);
            helper.createInitializedBlock(modified, new ByteArrayInputStream(decompressed));

            metadataSegments.remove(baseAddress);
        }

        // Create uninitialized blocks for all remaining segments.
        // TODO: This is not the correct way to approach things.
        for (SegmentInfo segment : metadataSegments.values()) {
            helper.createUninitializedBlock(segment);
        }
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }
}
