package space.joscomputing.BBGhidra.formats;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import java.io.IOException;
import java.util.ArrayList;

public class MappedLZMAReader {
    private static final int CHUNK_HEADER_LENGTH = 12;

    private final BinaryReader reader;
    /** The ending index of this mapping. */
    private final long mappingEndIndex;
    /** Individual sections contained within this mapping. */
    private final ArrayList<MappedSection> sections = new ArrayList<>();

    /** Creates a new MappedLZMAReader for this program. */
    public MappedLZMAReader(ByteProvider provider, long mappingBaseIndex, long mappingLength) {
        // TODO(spotlightishere): We should properly validate length.
        // Is there a BinaryReader subrange?
        this.reader = new BinaryReader(provider, true);
        reader.setPointerIndex(mappingBaseIndex);
        this.mappingEndIndex = mappingBaseIndex + mappingLength;
    }

    /** Interprets uninitialized within a mapping. */
    public void readMapping() throws IOException {
        MappedSection currentSection = new MappedSection();

        while (reader.getPointerIndex() + CHUNK_HEADER_LENGTH < mappingEndIndex) {
            // TODO(spotlightishere): Better understand the layout here.
            int tag = reader.readNextUnsignedShort();
            long loadAddress = reader.readNextUnsignedInt();
            int streamSize = reader.readNextUnsignedShort();
            int flagsUnknown = reader.readNextUnsignedShort();
            int flagsMaybe = reader.readNextUnsignedByte();
            int alignSize = reader.readNextUnsignedByte();

            // This seems to be used for uninitialized memory.
            boolean isBSSSegment = (flagsMaybe & 1) == 1;
            if (isBSSSegment) {
                // This is actual memory.
                currentSection.addUninitializedChunk(loadAddress, streamSize);
                continue;
            }

            // Read our stream data.
            byte[] streamContents = reader.readNextByteArray(streamSize);

            // If the alignment size is zero, this is probably raw mapped data.
            // TODO(spotlightishere): Is this correct?
            // This was only observed within the modem segment.
            if (alignSize == 0) {
                continue;
            }

            currentSection.addCompressedChunk(loadAddress, streamContents);

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

            // TODO: Is this a reliable way to determine section boundaries?
            if (streamSize != 0x4000 && streamSize != 0x3FF0) {
                // Add this current section to our list, and create a new one.
                sections.add(currentSection);
                currentSection = new MappedSection();
            }
        }
    }

    public ArrayList<MappedSection> getSections() {
        return sections;
    }
}
