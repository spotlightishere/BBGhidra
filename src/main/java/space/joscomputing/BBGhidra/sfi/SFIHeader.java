package space.joscomputing.BBGhidra.sfi;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import java.io.IOException;
import space.joscomputing.BBGhidra.helpers.SegmentInfo;

public class SFIHeader {
    /** Identifier at the start of every SFI. */
    private static final long SFI_MAGIC = 0x59AB797DL;
    /** Length of the SFI format header. */
    public static final long SFI_HEADER_LENGTH = 20;

    /** Minimum observed SFI format version. * */
    private static final int SFI_VERSION_MIN = 0x10000;
    /** Maximum observed SFI format version. * */
    private static final int SFI_VERSION_MAX = 0x10008;

    /** We only recognize one SFI image type. There appear to be several others across generations of BlackBerries. */
    private static final int SFI_TYPE_OS_IMAGE = 2;

    /** Identifier at the start of the OS image contents. */
    private static final long SFI_OS_MAGIC = 0xD7A82D1FL;
    /** Identifier at the start of the app image contents. */
    private static final long SFI_APP_MAGIC = 0xD7CC2D1FL;

    /** The offset of the app image's address within the info struct. */
    private static final long OS_INFO_APP_IMAGE_ADDR_OFFSET = 136;
    /** The offset of the compressed loader address within the info struct. */
    private static final long OS_INFO_LOADER_ADDR_OFFSET = OS_INFO_APP_IMAGE_ADDR_OFFSET + 4 + (17 * 4);

    /** The byte count of all eight ARMv6 vectors. */
    private static final long ARMV6_VECTORS_LENGTH = 8 * 4;

    private final long osOffset;
    private final long osBaseAddress;
    private final long osSize;

    private final long appOffset;
    private final long appBaseAddress;
    private final long appSize;

    private final long compressedOffset;

    /**
     * Determines whether the given SFI header is valid.
     *
     * @param provider The program to read from.
     * @return Whether the SFI format header seems sufficient.
     * @throws IOException Should the format not match.
     */
    public static boolean isValidHeader(ByteProvider provider) throws IOException {
        // This file format is little endian.
        BinaryReader reader = new BinaryReader(provider, true);

        // First, validate our SFI header.
        long magic = reader.readNextUnsignedInt();
        if (magic != SFI_MAGIC) {
            return false;
        }

        // TODO(spotlightishere): How do we handle different format versions?
        long formatVersion = reader.readNextUnsignedInt();
        if (formatVersion < SFI_VERSION_MIN) {
            throw new IOException("Unknown SFI format version!");
        }

        long imageFileType = reader.readNextUnsignedInt();
        if (imageFileType != SFI_TYPE_OS_IMAGE) {
            throw new IOException("Unhandled SFI image file type!");
        }

        return true;
    }

    /**
     * Determines image layouts within an SFI's contents.
     *
     * @param provider The program to read from, beginning with the SFI header.
     * @throws IOException Should the format not match.
     */
    public SFIHeader(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, true);

        // Our OS image begins beyond our SFI header.
        // It begins with its ARMv6 exception vectors.
        this.osOffset = SFI_HEADER_LENGTH;
        reader.setPointerIndex(osOffset + ARMV6_VECTORS_LENGTH);

        // TODO(spotlightishere): There may be multiple magic values for images.
        // This is based off of a BlackBerry Tour 9630's firmware.
        long osMagic = reader.readNextUnsignedInt();
        if (osMagic != SFI_OS_MAGIC) {
            throw new IOException("Unknown OS image header magic!");
        }

        this.osBaseAddress = reader.readNextUnsignedInt();
        long osBuildInfoAddress = reader.readNextUnsignedInt();

        // Then, the OS info block begins at its build info address.
        long osInfoOffset = addressToOffset(osBuildInfoAddress);
        // Read our app image address, and our loader address.
        long appImageAddress = reader.readUnsignedInt(osInfoOffset + OS_INFO_APP_IMAGE_ADDR_OFFSET);
        long loaderAddress = reader.readUnsignedInt(osInfoOffset + OS_INFO_LOADER_ADDR_OFFSET);

        // Wrap up our OS image.
        // It spans until the beginning of our app image.
        this.osSize = appImageAddress - osBaseAddress;

        // Next, parse our app image.
        this.appOffset = addressToOffset(appImageAddress);
        reader.setPointerIndex(appOffset);

        long appMagic = reader.readNextUnsignedInt();
        if (appMagic != SFI_APP_MAGIC) {
            throw new IOException("Unknown app image header magic!");
        }
        this.appBaseAddress = reader.readNextUnsignedInt();
        // Skip over the app's build info address.
        reader.readNextUnsignedInt();
        long appLoaderAddress = reader.readNextUnsignedInt();

        // Our app image spans until its compressed loader.
        this.appSize = appLoaderAddress - appBaseAddress;

        // Lastly, our compressed loader follows our app image.
        this.compressedOffset = addressToOffset(loaderAddress);
    }

    /** Maps an address within the SFI's contents to a file offset. */
    private long addressToOffset(long address) {
        return osOffset + (address - osBaseAddress);
    }

    public long getOsOffset() {
        return osOffset;
    }

    public SegmentInfo getOsSegmentInfo() {
        return new SegmentInfo(osBaseAddress, osSize, "os");
    }

    public long getAppOffset() {
        return appOffset;
    }

    public SegmentInfo getAppSegmentInfo() {
        return new SegmentInfo(appBaseAddress, appSize, "app");
    }

    public long getCompressedOffset() {
        return compressedOffset;
    }
}
