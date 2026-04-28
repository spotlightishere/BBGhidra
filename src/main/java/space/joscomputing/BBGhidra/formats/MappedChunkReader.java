package space.joscomputing.BBGhidra.formats;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import java.io.IOException;
import java.util.ArrayList;

public class MappedChunkReader {
    /** Magic for the chunked block format. */
    private static final long CHUNK_REGION_MAGIC = 0x77777777;

    private final BinaryReader reader;

    /** The sequencer of chunks within this reader. */
    private final MappedSequence sequencer = new MappedSequence();

    /** Creates a new MappedLZMAReader for this program. */
    public MappedChunkReader(ByteProvider provider, long mappingBaseIndex) {
        // TODO(spotlightishere): We should properly validate length.
        // Is there a BinaryReader subrange?
        this.reader = new BinaryReader(provider, true);
        reader.setPointerIndex(mappingBaseIndex);
    }

    /** Categorizes chunks within a mapping. */
    public void readMapping() throws IOException {
        long startPosition = reader.getPointerIndex();

        // First, we have a 12 byte header.
        long headerMagic = reader.readNextUnsignedInt();
        if (headerMagic != CHUNK_REGION_MAGIC) {
            throw new IOException("Invalid chunk region magic!");
        }
        long sectionLength = reader.readNextUnsignedInt();
        // TODO: How/where is this used?
        long sectionAddress = reader.readNextUnsignedInt();
        // That is, offset to the first compressed chunk,
        // skipping the binary for loading program.
        // We should probably mark that as a chunk...
        long chunkOffset = reader.readNextUnsignedInt();

        // TODO: Why +18?
        long adjustedPosition = startPosition + chunkOffset + 18;
        reader.setPointerIndex(adjustedPosition);

        long endPosition = startPosition + sectionLength;

        // Continue until all data is exhausted.
        while (true) {
            long currentPosition = reader.getPointerIndex();
            if ((currentPosition + 12) >= endPosition) {
                // We're complete!
                break;
            }

            // TODO(spotlightishere): Better understand the layout here.
            // The `zero` var appears to go unused.
            int chunkType = reader.readNextUnsignedShort();
            long loadAddress = reader.readNextUnsignedInt();
            int streamSize = reader.readNextUnsignedShort();
            int zero = reader.readNextUnsignedShort();
            int flags = reader.readNextUnsignedShort();

            // This seems to be used for uninitialized memory.
            boolean isBSSSegment = (flags & RawChunkFlags.NO_DATA) != 0;
            if (isBSSSegment) {
                // This is actual memory.
                sequencer.addUninitializedChunk(flags, loadAddress, streamSize);
                continue;
            }

            // Before anything else, align our stream.
            int disparity = streamSize % 4;
            if (disparity != 0) {
                // This is a little odd...
                // If our disparity is 1, we need to revert one byte.
                // Similarly, if our disparity is two, we revert two bytes.
                // If our disparity is 3, we need to advance one byte.
                if (disparity == 1) {
                    streamSize -= 1;
                } else if (disparity == 3) {
                    streamSize += 1;
                } else {
                    streamSize -= 2;
                }
            }

            // Read our stream data, and retain for later.
            byte[] streamContents = reader.readNextByteArray(streamSize);
            sequencer.addChunk(flags, loadAddress, streamContents);
        }
    }

    /** Read all chunk mappings and parse them sequentially. */
    public ArrayList<MappedSection> parseMappings() throws IOException {
        this.readMapping();
        return sequencer.sequence();
    }
}
