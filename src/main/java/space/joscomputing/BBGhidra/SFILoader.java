package space.joscomputing.BBGhidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import java.io.IOException;
import java.util.*;

public class SFILoader extends AbstractProgramWrapperLoader {
    @Override
    public String getName() {
        return "BlackBerry Signed File Image";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Examine the bytes in 'provider' to determine if this loader can load it.  If it
        // can load it, return the appropriate load specifications.

        return loadSpecs;
    }

    @Override
    protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
        // Load the bytes from 'settings.provider()' into the 'program'.
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }
}
