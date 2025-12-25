package space.joscomputing.BBGhidra.formats;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.tukaani.xz.LZMAInputStream;

public class MappedLZMAReader {
    private static final int SEGMENT_HEADER_LENGTH = 12;

    private AddressSpace addressSpace;
    private ByteProvider provider;
    private Program program;
    private TaskMonitor monitor;

    /** Creates a new MappedLZMAReader for this program. * */
    public MappedLZMAReader(ByteProvider provider, Program program, Loader.ImporterSettings settings) {
        this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        this.provider = provider;
        this.program = program;
        this.monitor = settings.monitor();
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
            chunkStream.write(streamContents);

            // If the alignment size is zero, this is probably mapped memory.
            // TODO(spotlightishere): Implement
            if (alignSize == 0) {
                continue;
            }

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
                System.out.println(-sizeDifference);
                long currentPos = reader.getPointerIndex();
                reader.setPointerIndex(currentPos + (-sizeDifference));
            }

            // Temporarily skip modem segment 4.
            if (segmentNameBase.equals("modem") && baseAddress == 0x00107FE0) {
                segmentIndex += 1;
                chunkStream = new ByteArrayOutputStream();
                needsChunk = true;
                continue;
            }

            // TODO: This is hacky. We should find other ways.
            if (streamSize != 0x4000 && streamSize != 0x3FF0) {
                byte[] fullStream = chunkStream.toByteArray();
                ByteArrayInputStream inputStream = new ByteArrayInputStream(fullStream);

                LZMAInputStream decompressStream = new LZMAInputStream(inputStream);
                decompressStream.enableRelaxedEndCondition();

                Address startingAddress = addressSpace.getAddress(chunkAddress);
                MemoryBlockUtils.createInitializedBlock(
                        program,
                        false,
                        String.format("%s_%d", segmentNameBase, segmentIndex),
                        startingAddress,
                        decompressStream,
                        fullStream.length,
                        "",
                        null,
                        true,
                        true,
                        true,
                        null,
                        monitor);

                segmentIndex += 1;

                // Reset state.
                chunkStream = new ByteArrayOutputStream();
                needsChunk = true;
            }
        }
    }
}
