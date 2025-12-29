package space.joscomputing.BBGhidra.helpers;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.opinion.Loader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import java.io.InputStream;

/** Assists us in not writing 12 arguments repeatedly. */
public class MemoryHelper {
    private final Program program;
    private final Loader.ImporterSettings settings;
    private final AddressSpace addressSpace;

    public MemoryHelper(Program program, Loader.ImporterSettings settings) {
        this.program = program;
        this.settings = settings;
        this.addressSpace = program.getAddressFactory().getDefaultAddressSpace();
    }

    /** Analogous to MemoryBlockUtils.createInitializedBlock but with lesser arguments. */
    public void createInitializedBlock(SegmentInfo blockInfo, InputStream inputStream) throws AddressOverflowException {
        Address baseAddress = addressSpace.getAddress(blockInfo.blockAddress());

        MemoryBlockUtils.createInitializedBlock(
                program,
                false,
                blockInfo.segmentName(),
                baseAddress,
                inputStream,
                blockInfo.blockSize(),
                "",
                null,
                true,
                true,
                true,
                settings.log(),
                settings.monitor());
    }

    public void createUninitializedBlock(SegmentInfo blockInfo) throws AddressOverflowException {
        Address baseAddress = addressSpace.getAddress(blockInfo.blockAddress());

        MemoryBlockUtils.createUninitializedBlock(
                program,
                false,
                blockInfo.segmentName(),
                baseAddress,
                blockInfo.blockSize(),
                "",
                null,
                true,
                true,
                true,
                settings.log());
    }
}
