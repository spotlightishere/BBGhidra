package space.joscomputing.BBGhidra.formats;

import ghidra.app.util.bin.BinaryReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import space.joscomputing.BBGhidra.helpers.ByteArrayReader;
import space.joscomputing.BBGhidra.helpers.SegmentInfo;

/**
 * Non-exhaustive handling. Please refer to the Kaitai Struct definition. <br>
 * We parse a minimal subset to annotate segments.
 */
public class BootInfoMetadata {
    private final BinaryReader reader;

    public static final int OP_HEADER = 1;
    public static final int OP_END = 2;
    public static final int OP_ADD_NEW_MS = 4;
    public static final int OP_STRUCT_EXPORT = 23;

    public BootInfoMetadata(byte[] bootInfo) {
        this.reader = new ByteArrayReader(bootInfo);
    }

    /** Returns segment info as defined in metadata. */
    public HashMap<Long, SegmentInfo> parseEntries() throws IOException {
        // We'll collect base, struct `one` definitive entries, and struct `three` sized.
        ArrayList<SegmentInfo> baseSegment = new ArrayList<>();
        ArrayList<SegmentInfo> structOne = new ArrayList<>();
        ArrayList<SegmentInfo> structThree = new ArrayList<>();

        // Used for validation.
        boolean seenHeader = false;
        while (true) {
            int entrySize = reader.readNextUnsignedShort();
            int entryType = reader.readNextUnsignedShort();

            // Special case: OP_END consumes no bytes.
            if (entryType == OP_END) {
                break;
            }

            // The above two values consume 4 bytes,
            // thus our contents size is (entrySize - 4).
            byte[] contents = reader.readNextByteArray(entrySize - 4);
            ByteArrayReader contentsReader = new ByteArrayReader(contents);
            switch (entryType) {
                case OP_HEADER:
                    seenHeader = true;
                    break;
                case OP_ADD_NEW_MS:
                    // This contains 8 uint32_t:
                    //   owner, base, size, flags, attr,
                    //   physpool, virtpool, zone
                    // It's then followed by name.
                    //
                    // For right now, we only care about the base (1), size (2), and name.
                    long[] msFields = contentsReader.readNextUnsignedIntArray(8);
                    String msName = contentsReader.readNextAsciiStringToEnd();

                    baseSegment.add(new SegmentInfo(msFields[1], msFields[2], msName));
                    break;
                case OP_STRUCT_EXPORT:
                    // Similarly, we have 9 uint32_t here:
                    //   pd, one, two, three, four,
                    //   five, six, objType, id
                    // Again, followed by the struct's name.
                    long[] structFields = contentsReader.readNextUnsignedIntArray(9);
                    String structName = contentsReader.readNextAsciiStringToEnd();

                    // The struct's contents appears to hinge on the contents of `one`.
                    switch ((int) structFields[1]) {
                        case 0:
                            // When `one` is zero, it often refers to physical HWIO memory.
                            // We cannot perform any further operation.
                            break;
                        case 1:
                            // If `one` is set to `1`, then field `two` holds its address.
                            // These names appear to be more accurate than the default case.
                            // However, no size is provided in other fields, so this is simply for naming.
                            structOne.add(new SegmentInfo(structFields[2], 0, structName));
                            break;
                        default:
                            // Otherwise, `one` is virtual, `three` is physical.
                            // The virtual and physical addresses may match.
                            // `five` then contains its decompressed size, where `six` contains its total size.
                            // TODO(spotlightishere): We may need to remap various segments accordingly.
                            // For right now, we'll preserve physical.
                            structThree.add(new SegmentInfo(structFields[3], structFields[6], structName));
                            break;
                    }
                default:
                    // TODO: Maybe error on unknown types?
                    break;
            }
        }

        if (!seenHeader) {
            // TODO: Throw more specific error
            throw new IOException("No header within BootInfo metadata!");
        }

        // We'll now combine all.
        HashMap<Long, SegmentInfo> completeInfo = new HashMap<>();

        // First, insert all base entries as-is.
        for (SegmentInfo baseInfo : baseSegment) {
            completeInfo.put(baseInfo.blockAddress(), baseInfo);
        }

        // Next, overwrite sizes and names based on structThree.
        for (SegmentInfo threeInfo : structThree) {
            completeInfo.put(threeInfo.blockAddress(), threeInfo);
        }

        // Finally, update names based on structOne.
        for (SegmentInfo oneInfo : structOne) {
            long currentAddress = oneInfo.blockAddress();
            SegmentInfo current = completeInfo.get(currentAddress);
            if (current == null) {
                throw new IOException("Mismatch between described metadata in BootInfo!");
            }

            SegmentInfo updated = new SegmentInfo(currentAddress, current.blockSize(), oneInfo.segmentName());
            completeInfo.put(currentAddress, updated);
        }

        return completeInfo;
    }
}
