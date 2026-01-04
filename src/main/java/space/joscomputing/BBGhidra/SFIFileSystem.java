package space.joscomputing.BBGhidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import space.joscomputing.BBGhidra.formats.SFIHeader;
import space.joscomputing.BBGhidra.helpers.SFIImageType;

/** Provide class-level documentation that describes what this file system does. */
@FileSystemInfo(
        type = SFIFileSystem.FS_TYPE,
        description = "BlackBerry Signed File Image",
        factory = SFIFileSystem.SFIFileSystemFactory.class)
public class SFIFileSystem implements GFileSystem {
    /** Our public file system type, referenced within our loader. */
    public static final String FS_TYPE = "sfi";

    private final FSRLRoot fsFSRL;
    private FileSystemIndexHelper<SFIImageType> fsih;
    private final FileSystemRefManager refManager = new FileSystemRefManager(this);

    private ByteProvider provider;
    private final SFIHeader header;

    /**
     * File system constructor.
     *
     * @param fsFSRL The root {@link FSRL} of the file system.
     * @param provider The file system provider.
     */
    public SFIFileSystem(FSRLRoot fsFSRL, ByteProvider provider) throws IOException {
        this.fsFSRL = fsFSRL;
        this.provider = provider;
        this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);

        // TODO(spotlightishere): This is a hack.
        // Begin reading at the true SFI file format header.
        this.header = new SFIHeader(provider);
    }

    /** Helper to get the file size for an image type. */
    private long getImageSize(SFIImageType imageType) {
        return switch (imageType) {
            case APP ->
                // This size is technically incorrect, but this works well enough for now.
                header.getAppSegmentInfo().blockSize()
                        + header.getOsSegmentInfo().blockSize()
                        + header.getL4Size();
            case MODEM ->
                // Our modem image is more straightforward.
                header.getModemSize();
        };
    }

    /**
     * Mounts (opens) the file system.
     *
     * @param monitor A cancellable task monitor.
     */
    public void mount(TaskMonitor monitor) {
        monitor.setMessage("Opening " + SFIFileSystem.class.getSimpleName() + "...");

        // Create a file for every registered image type.
        for (SFIImageType currentType : SFIImageType.values()) {
            String filename = currentType.getImageFilename();
            long size = getImageSize(currentType);

            fsih.storeFile(filename, fsih.getFileCount(), false, size, currentType);
        }
    }

    @Override
    public void close() throws IOException {
        refManager.onClose();
        if (provider != null) {
            provider.close();
            provider = null;
        }
        fsih.clear();
    }

    @Override
    public String getName() {
        return fsFSRL.getContainer().getName();
    }

    @Override
    public FSRLRoot getFSRL() {
        return fsFSRL;
    }

    @Override
    public boolean isClosed() {
        return provider == null;
    }

    @Override
    public int getFileCount() {
        return fsih.getFileCount();
    }

    @Override
    public FileSystemRefManager getRefManager() {
        return refManager;
    }

    @Override
    public GFile lookup(String path) throws IOException {
        return fsih.lookup(path);
    }

    @Override
    public GFile lookup(String path, Comparator<String> nameComp) throws IOException {
        return fsih.lookup(null, path, nameComp);
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) throws IOException, CancelledException {
        SFIImageType imageType = fsih.getMetadata(file);
        if (imageType == null) {
            return null;
        }

        return switch (imageType) {
            case SFIImageType.APP ->
                // TODO(spotlightishere): This is a hack!
                // Right now, we wrap our entire provider (beyond its detectable header).
                // The app image currently must load additional BlackBerry assets within the SFI.
                // It may be beneficial to properly segment this going forward.
                new ByteProviderWrapper(
                        provider,
                        SFIHeader.SFI_HEADER_LENGTH,
                        provider.length() - SFIHeader.SFI_HEADER_LENGTH,
                        file.getFSRL());
            case SFIImageType.MODEM ->
                // For modem, we have a contiguous block that can be parsed.
                new ByteProviderWrapper(provider, header.getModemOffset(), header.getModemSize(), file.getFSRL());
        };
    }

    @Override
    public List<GFile> getListing(GFile directory) throws IOException {
        return fsih.getListing(directory);
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        SFIImageType imageType = fsih.getMetadata(file);
        if (imageType == null) {
            return null;
        }

        FileAttributes result = new FileAttributes();
        result.add(FileAttributeType.NAME_ATTR, imageType.getImageFilename());
        result.add(FileAttributeType.SIZE_ATTR, getImageSize(imageType));

        // We insert a custom image type property for our loader to leverage.
        result.add(SFIImageType.IMAGE_TYPE_PROPERTY, imageType);
        return result;
    }

    public static class SFIFileSystemFactory
            implements GFileSystemFactoryByteProvider<SFIFileSystem>, GFileSystemProbeByteProvider {

        @Override
        public SFIFileSystem create(
                FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
                throws IOException, CancelledException {
            // Our SFIFileSystem will parse the SFI header upon construction.
            SFIFileSystem fs = new SFIFileSystem(targetFSRL, byteProvider);
            fs.mount(monitor);
            return fs;
        }

        @Override
        public boolean probe(ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
                throws IOException, CancelledException {
            return SFIHeader.isValidHeader(byteProvider);
        }
    }
}
