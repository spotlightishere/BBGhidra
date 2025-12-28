package space.joscomputing.BBGhidra.formats;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.tukaani.xz.ArrayCache;
import org.tukaani.xz.LZMAInputStream;

public class MappedLZMAReader {
    private static final int SEGMENT_HEADER_LENGTH = 12;

    private final AddressSpace addressSpace;
    private final ByteProvider provider;
    private final Program program;
    private final TaskMonitor monitor;
    private final MessageLog logger;

    /** Creates a new MappedLZMAReader for this program. * */
    public MappedLZMAReader(ByteProvider provider, Program program, Loader.ImporterSettings settings) {
        this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        this.provider = provider;
        this.program = program;
        this.monitor = settings.monitor();
        this.logger = settings.log();
    }

    public void readSegment(long segmentAddress, long segmentLength, String segmentNameBase)
            throws IOException, AddressOverflowException {
        BinaryReader reader = new BinaryReader(provider, true);
        reader.setPointerIndex(segmentAddress);

        // TODO(spotlightishere): We should properly validate length.
        // Is there a BinaryReader subrange?
        // Start with an unfinished chunk so our base address is updated.
        boolean needsChunk = true;
        long chunkAddress = 0;
        ByteArrayOutputStream chunkStream = new ByteArrayOutputStream();
        int segmentIndex = 0;

        long segmentEndAddr = segmentAddress + segmentLength;
        while (reader.getPointerIndex() + SEGMENT_HEADER_LENGTH < segmentEndAddr) {
            // TODO(spotlightishere): Better understand the layout here.
            int tag = reader.readNextUnsignedShort();
            long baseAddress = reader.readNextUnsignedInt();

            if (needsChunk) {
                chunkAddress = baseAddress;
                needsChunk = false;
            }
            int streamSize = reader.readNextUnsignedShort();
            int flagsUnknown = reader.readNextUnsignedShort();
            int flagsMaybe = reader.readNextUnsignedByte();
            int alignSize = reader.readNextUnsignedByte();

            // This seems to be used for memory.
            boolean isBSSSegment = (flagsMaybe & 1) == 1;
            if (isBSSSegment) {
                // This is actual memory.
                // TODO(spotlightishere): Implement
                continue;
            }

            // Read our stream data.
            byte[] streamContents = reader.readNextByteArray(streamSize);

            // If the alignment size is zero, this is probably mapped memory.
            // TODO(spotlightishere): Implement
            if (alignSize == 0) {
                continue;
            }

            chunkStream.write(streamContents);

            // The alignment size of 6 (as used within L4) appears to truly be 4.
            // (Perhaps this indicates something other than alignment?)
            if (alignSize == 6) {
                alignSize = 4;
            }

            // We may need to fix up the size difference for some streams.
            int sizeDifference = streamSize % alignSize;
            if (sizeDifference == 3) {
                sizeDifference = -1;
            }

            if (sizeDifference != 0) {
                long currentPos = reader.getPointerIndex();
                reader.setPointerIndex(currentPos + (-sizeDifference));
            }

            // TODO: This is hacky. We should find other ways.
            if (streamSize != 0x4000 && streamSize != 0x3FF0) {
                byte[] inputBytes = chunkStream.toByteArray();

                // Refer to `createLzmaStream` on why we do not directly create an `LZMAInputStream`.
                try (ByteArrayInputStream inputStream = new ByteArrayInputStream(inputBytes);
                        LZMAInputStream lzmaStream = createLzmaStream(inputStream)) {
                    // Fully decompress the LZMA stream.
                    byte[] decompressed = lzmaStream.readAllBytes();
                    ByteArrayInputStream decompressedStream = new ByteArrayInputStream(decompressed);

                    Address startingAddress = addressSpace.getAddress(chunkAddress);
                    MemoryBlockUtils.createInitializedBlock(
                            program,
                            false,
                            String.format("%s_%d", segmentNameBase, segmentIndex),
                            startingAddress,
                            decompressedStream,
                            decompressed.length,
                            "",
                            null,
                            true,
                            true,
                            true,
                            logger,
                            monitor);
                }

                segmentIndex += 1;

                // Reset state.
                chunkStream = new ByteArrayOutputStream();
                needsChunk = true;
            }
        }
    }

    /**
     * The streams embedded within this format are LZMA1, also known as "LZMA Alone". Within its 13-byte header, a
     * 64-bit uncompressed size exists. <br>
     * Unlike the normal LZMA file format, these streams use those 8 bytes to store their compressed and uncompressed
     * size as 32-bit fields.
     *
     * @param inputStream The raw LZMA input in LZMA1 ("LZMA Alone") format.
     * @return The custom input stream reader with a correct size.
     */
    LZMAInputStream createLzmaStream(ByteArrayInputStream inputStream) throws IOException {
        // This is more or less an edit of the default LZMAInputStream constructor.
        // We leverage Ghidra's ByteProvider for ease.
        //
        // First, read our properties byte (lc, lp, and pb).
        byte propsByte = (byte) inputStream.read();

        // Our dictionary size is an unsigned 32-bit little endian integer.
        int dictSize = 0;
        for (int i = 0; i < 4; ++i) dictSize |= inputStream.read() << (8 * i);

        // Here begins our modifications. Our next value is our compressed
        // size as a 32-bit little endian integer.
        // We have no way to compare against this, so we'll simply read past it.
        inputStream.skipNBytes(4);

        // Next, we have our uncompressed size as a 32-bit little endian integer.
        long uncompSize = 0;
        for (int i = 0; i < 4; ++i) uncompSize |= (long) inputStream.read() << (8 * i);

        // Create a default ArrayCache for use.
        ArrayCache cache = ArrayCache.getDefaultCache();

        return new LZMAInputStream(inputStream, uncompSize, propsByte, dictSize, null, cache);
    }
}
