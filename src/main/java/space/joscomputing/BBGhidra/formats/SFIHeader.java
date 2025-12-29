package space.joscomputing.BBGhidra.formats;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import java.io.IOException;
import space.joscomputing.BBGhidra.helpers.SegmentInfo;

public class SFIHeader {
    private static final long SFI_MAGIC = 0x59AB797DL;
    private static final long SFI_HEADER_LENGTH = 20;

    /** Minimum observed SFI format version. * */
    private static final int SFI_VERSION_MIN = 0x10000;
    /** Maximum observed SFI format version. * */
    private static final int SFI_VERSION_MAX = 0x10008;

    /** We only recognize one SFI image type. There appear to be several others across generations of BlackBerries. */
    private static final int SFI_TYPE_OS_IMAGE = 2;

    private static final long SFI_OS_MAGIC = 0xD7A82D1FL;
    private static final long SFI_OS_HEADER_SIZE = 20;
    private static final long SFI_APP_IMAGE_MAIN_OFFSET = 116;
    private static final long SFI_APP_MAGIC = 0xD7CC2D1FL;
    private static final long SFI_SIGNATURE_MAGIC = 0xD7C82D1FL;

    private final long osImageOffset;
    private final long osBaseAddress;
    private final long osSize;

    private final long appImageOffset;
    private final long appBaseAddress;
    private final long appSize;

    private final long modemOffset;
    private final long modemSize;

    private final long l4Offset;
    private final long l4Size;

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

        // First, parse our actual SFI header.
        long magic = reader.readNextUnsignedInt();
        if (magic != SFI_MAGIC) {
            return false;
        }

        // TODO(spotlightishere): How do we handle different format versions?
        long version = reader.readNextUnsignedInt();
        if (version < SFI_VERSION_MIN || version > SFI_VERSION_MAX) {
            throw new IOException("Unknown SFI version!");
        }

        long formatType = reader.readNextUnsignedInt();
        if (formatType != SFI_TYPE_OS_IMAGE) {
            throw new IOException("Unhandled SFI image type!");
        }

        return true;
    }

    /**
     * Parses the SFI header alongside image layouts within.
     *
     * @param provider The program to read from.
     * @throws IOException Should the format not match.
     */
    public SFIHeader(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, true);

        // Within our SFI header, we have fields like version information.
        // Our OS image contains its magic bytes beyond its ARMv6 reset vectors.
        // Mark the true offset, but skip beyond this header.
        //
        // This is:
        // - 20 bytes for header
        // - 4 bytes for (possibly?) image count
        // - 28 bytes for ARMv6 reset vectors
        this.osImageOffset = SFI_HEADER_LENGTH;
        reader.setPointerIndex(osImageOffset + 4 + 28);

        // TODO(spotlightishere): There may be multiple magic values for images.
        // This is based off of a BlackBerry Tour 9630's firmware.
        long osHeaderMagic = reader.readNextUnsignedInt();
        if (osHeaderMagic != SFI_OS_MAGIC) {
            throw new IOException("Unknown OS image header magic!");
        }

        this.osBaseAddress = reader.readNextUnsignedIntExact();
        long osEndAddress = reader.readNextUnsignedInt();

        // TODO(spotlightishere): This is hacky!
        // We skip to the end of the OS base address,
        // reading the info block proceeding its signature.
        //
        // In our file, that's:
        // (20 bytes for SFI) + (20 for OS image header) + osSize.
        //
        // Within our signature block, we can read the main application's
        // address. Its address is present 116 bytes in.
        final long osBinarySize = osEndAddress - osBaseAddress;
        final long appMainAddressOffset =
                SFI_HEADER_LENGTH + SFI_OS_HEADER_SIZE + osBinarySize + SFI_APP_IMAGE_MAIN_OFFSET;
        final long appMainAddress = reader.readUnsignedInt(appMainAddressOffset);

        // We adjust OS size to match from its start to before address's beginning.
        this.osSize = appMainAddress - osBaseAddress;

        // Finally, we must adjust the offset to adapt for our SFI's header length.
        this.appImageOffset = SFI_HEADER_LENGTH + appMainAddress - osBaseAddress;
        reader.setPointerIndex(appImageOffset);

        long appHeaderMagic = reader.readNextUnsignedInt();
        if (appHeaderMagic != SFI_APP_MAGIC) {
            throw new IOException("Unknown app image header magic!");
        }
        this.appBaseAddress = reader.readNextUnsignedInt();
        long appEndAddress = reader.readNextUnsignedInt();
        this.appSize = appEndAddress - appBaseAddress;

        // TODO(spotlightishere): Properly calculate offsets based on SFI_SIGNATURE_MAGIC
        // For right now, implementing decompression is more important.
        this.modemOffset = 0x6F2BBAL;
        this.modemSize = 8238400;
        this.l4Offset = 0xF7A98EL;
        this.l4Size = 5100286;
    }

    public long getOsImageOffset() {
        return osImageOffset;
    }

    public SegmentInfo getOsSegmentInfo() {
        return new SegmentInfo(osBaseAddress, osSize, "os");
    }

    public long getAppImageOffset() {
        return appImageOffset;
    }

    public SegmentInfo getAppSegmentInfo() {
        return new SegmentInfo(appBaseAddress, appSize, "app");
    }

    public long getModemOffset() {
        return modemOffset;
    }

    public long getModemSize() {
        return modemSize;
    }

    public long getL4Offset() {
        return l4Offset;
    }

    public long getL4Size() {
        return l4Size;
    }
}
