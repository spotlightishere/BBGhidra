package space.joscomputing.BBGhidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import space.joscomputing.BBGhidra.formats.BootInfoMetadata;
import space.joscomputing.BBGhidra.formats.MappedLZMAReader;
import space.joscomputing.BBGhidra.formats.MappedSection;
import space.joscomputing.BBGhidra.formats.SFIHeader;
import space.joscomputing.BBGhidra.helpers.MemoryHelper;
import space.joscomputing.BBGhidra.helpers.SegmentInfo;

public class SFILoader extends AbstractProgramWrapperLoader {
    // Used while loading.

    @Override
    public String getName() {
        return "BlackBerry Signed File Image";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Validate our SFI header. If it seems acceptable,
        // we'll parse the OS and app headers within load.
        if (SFIHeader.isValidHeader(provider)) {
            // TODO(spotlightishere): The baseband is ARMv4t, whereas main app processor is ARMv6t.
            // We should probably split the files into two segments.
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v6", "default"), true));
        }

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
        SFIHeader header = new SFIHeader(provider);
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        MemoryHelper helper = new MemoryHelper(program, settings);

        // First, import OS as-is.
        // OS will always be our base address.
        SegmentInfo osInfo = header.getOsSegmentInfo();
        Address osBaseAddress = addressSpace.getAddress(osInfo.blockAddress());
        program.setImageBase(osBaseAddress, true);

        InputStream osImage = provider.getInputStream(header.getOsImageOffset());
        helper.createInitializedBlock(header.getOsSegmentInfo(), osImage);

        // Similarly, import app as-is.
        InputStream appImage = provider.getInputStream(header.getAppImageOffset());
        helper.createInitializedBlock(header.getAppSegmentInfo(), appImage);

        // Parse and unpack our LZMA-compressed segments.
        MappedLZMAReader l4Mapping = new MappedLZMAReader(provider, header.getL4Offset(), header.getL4Size());
        l4Mapping.readMapping();

        // TODO: Probably create uninitialized blocks,
        // but boot info might also match?
        //
        // The last segment in our LZMA-compressed segments is okL4's BootInfo.
        // We parse this to obtain segment names and other mappings (e.g. heap).
        MappedSection lastSection = l4Mapping.getSections().getLast();
        BootInfoMetadata metadata = new BootInfoMetadata(lastSection.decompress());
        HashMap<Long, SegmentInfo> metadataSegments = metadata.parseEntries();

        // For all compressed sections, get the corresponding segment metadata.
        for (MappedSection section : l4Mapping.getSections()) {
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

        // TODO: We need to provide the SFI as a filesystem to Ghidra.
        // We'll parse modem separately.
        // reader.readSegment(header.getModemOffset(), header.getModemSize(), "modem");
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }
}
