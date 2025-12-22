package space.joscomputing.BBGhidra;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import space.joscomputing.BBGhidra.formats.MappedLZMAReader;
import space.joscomputing.BBGhidra.formats.SFIHeader;

public class SFILoader extends AbstractProgramWrapperLoader {
    @Override
    public String getName() {
        return "BlackBerry Signed File Image";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Validate our SFI header. If it seems acceptable,
        // we'll parse the OS and app headers within load.
        if (SFIHeader.isValidHeader(provider)) {
            // TODO(spotlightishere): The baseband is ARMv4t, whereas main app processor is ARMv6t.
            // We should probably split the files into two segments.
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v6", "default"), true));
        }

        return loadSpecs;
    }

    @Override
    protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
        try (ByteProvider provider = settings.provider()) {
            loadForReal(provider, program, settings);
        } catch (IOException | AddressOverflowException | LockException e) {
            throw new LoadException(e);
        }
    }

    private void loadForReal(ByteProvider provider, Program program, ImporterSettings settings)
            throws IOException, AddressOverflowException, LockException {
        SFIHeader header = new SFIHeader(provider);
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();

        // First, import OS as-is.
        // OS will always be our base address.
        Address osBaseAddress = addressSpace.getAddress(header.getOsBaseAddress());
        program.setImageBase(osBaseAddress, true);

        InputStream osImage = provider.getInputStream(header.getOsImageOffset());
        MemoryBlockUtils.createInitializedBlock(
                program,
                false,
                "os",
                osBaseAddress,
                osImage,
                header.getOsSize(),
                "",
                null,
                true,
                true,
                true,
                null,
                settings.monitor());

        // Similarly, import app as-is.
        Address appBaseAddress = addressSpace.getAddress(header.getAppBaseAddress());
        InputStream appImage = provider.getInputStream(header.getAppImageOffset());
        MemoryBlockUtils.createInitializedBlock(
                program,
                false,
                "app",
                appBaseAddress,
                appImage,
                header.getAppSize(),
                "",
                null,
                true,
                true,
                true,
                null,
                settings.monitor());

        // Unpack our LZMA-compressed segments.
        MappedLZMAReader reader = new MappedLZMAReader(provider, program, settings);
        reader.readSegment(header.getModemOffset(), header.getModemSize(), "modem");
        reader.readSegment(header.getL4Offset(), header.getL4Size(), "L4");
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }
}
