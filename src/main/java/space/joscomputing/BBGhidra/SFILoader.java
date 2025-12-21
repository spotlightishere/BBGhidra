package space.joscomputing.BBGhidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import java.io.IOException;
import java.util.*;
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
        // Load the bytes from 'settings.provider()' into the 'program'.

    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.SPECIALIZED_TARGET_LOADER;
    }
}
