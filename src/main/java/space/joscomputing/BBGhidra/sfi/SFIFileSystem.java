package space.joscomputing.BBGhidra.sfi;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.formats.gfilesystem.fileinfo.FileAttributeType;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;

/** Provide class-level documentation that describes what this file system does. */
@FileSystemInfo(
        type = SFIFileSystem.FS_TYPE,
        description = "BlackBerry Signed File Image",
        factory = SFIFileSystem.SFIFileSystemFactory.class,
        extensions = {"sfi"})
public class SFIFileSystem implements GFileSystem {
    /** Our public file system type, referenced within our loader. */
    public static final String FS_TYPE = "sfi";

    private final FSRLRoot fsFSRL;
    private final FileSystemIndexHelper<SFIImageType> fsih;
    private final FileSystemRefManager refManager = new FileSystemRefManager(this);

    private ByteProvider provider;
    /** The length of the wrapping container image. */
    private final long containerSize;

    /**
     * File system constructor.
     *
     * @param fsFSRL The root {@link FSRL} of the file system.
     * @param provider The file system provider.
     */
    public SFIFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
        this.fsFSRL = fsFSRL;
        this.provider = provider;
        this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);

        // TODO(spotlightishere): This is a hack.
        // Begin reading at the true SFI file format header.
        this.containerSize = provider.length();
    }

    /**
     * Mounts (opens) the file system.
     *
     * @param monitor A cancellable task monitor.
     */
    public void mount(TaskMonitor monitor) throws IOException {
        monitor.setMessage("Opening " + SFIFileSystem.class.getSimpleName() + "...");

        // Create a file for every registered image type.
        for (SFIImageType currentType : SFIImageType.values()) {
            String filename = currentType.getImageFilename();

            fsih.storeFile(filename, fsih.getFileCount(), false, containerSize, currentType);
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
    public GFile lookup(String path) {
        return fsih.lookup(path);
    }

    @Override
    public GFile lookup(String path, Comparator<String> nameComp) {
        return fsih.lookup(null, path, nameComp);
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor) {
        SFIImageType imageType = fsih.getMetadata(file);
        if (imageType == null) {
            return null;
        }

        // TODO(spotlightishere): This is a hack!
        // Right now, we wrap our entire provider (beyond its detectable header).
        // The app image currently must load additional BlackBerry assets within the SFI.
        //
        // It may be beneficial to properly segment this beforehand.
        return new ByteProviderWrapper(provider, 0, containerSize, file.getFSRL());
    }

    @Override
    public List<GFile> getListing(GFile directory) {
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
        // TODO: This size doesn't account for decompressed contents.
        // We'll simply mirror the input container format size.
        result.add(FileAttributeType.SIZE_ATTR, this.containerSize);

        // We insert a custom image type property for our loader to leverage.
        result.add(SFIImageType.IMAGE_TYPE_PROPERTY, imageType);
        return result;
    }

    public static class SFIFileSystemFactory
            implements GFileSystemFactoryByteProvider<SFIFileSystem>, GFileSystemProbeByteProvider {

        @Override
        public SFIFileSystem create(
                FSRLRoot targetFSRL, ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
                throws IOException {
            // Our SFIFileSystem will parse the SFI header upon construction.
            SFIFileSystem fs = new SFIFileSystem(targetFSRL, byteProvider);
            fs.mount(monitor);
            return fs;
        }

        @Override
        public boolean probe(ByteProvider byteProvider, FileSystemService fsService, TaskMonitor monitor)
                throws IOException {
            return SFIHeader.isValidHeader(byteProvider);
        }
    }
}
