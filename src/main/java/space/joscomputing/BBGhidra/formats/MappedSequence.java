package space.joscomputing.BBGhidra.formats;

import java.io.IOException;
import java.util.ArrayList;

/** A class to help sequence all parsed chunks. */
public class MappedSequence {
    /** All chunks, prior to processing. */
    private final ArrayList<RawChunk> tracked = new ArrayList<>();

    public MappedSequence() {}

    /** Tracks an uninitialized chunk. */
    public void addUninitializedChunk(int flags, long loadAddress, int chunkSize) {
        byte[] payload = new byte[chunkSize];
        RawChunk current = new RawChunk(flags, loadAddress, payload);
        tracked.add(current);
    }

    /** Tracks a chunk representing data. */
    public void addChunk(int flags, long loadAddress, byte[] payload) {
        RawChunk current = new RawChunk(flags, loadAddress, payload);
        tracked.add(current);
    }

    /** Sequences all raw chunks, returning logical sections. */
    public ArrayList<MappedSection> sequence() throws IOException {
        ArrayList<ArrayList<RawChunk>> total = new ArrayList<>();
        ArrayList<RawChunk> current = new ArrayList<>();

        // First, divide all chunks into incremental addresses.
        for (RawChunk currentChunk : tracked) {
            if (current.isEmpty()) {
                // Begin this sequence, if necessary.
                current.add(currentChunk);
                continue;
            }

            // The previous chunk must continue to this chunk.
            RawChunk previousChunk = current.getLast();
            long sequentialAddress = previousChunk.loadAddress() + previousChunk.payloadSize();
            if (currentChunk.loadAddress() == sequentialAddress) {
                // This properly continues the sequence.
                current.add(currentChunk);
                continue;
            }

            // Otherwise, this is a non-sequential chunk.
            // Conclude this sequence.
            total.add(current);
            current = new ArrayList<>();
            current.add(currentChunk);
        }

        // Add our last sequence if not otherwise concluded.
        if (!current.isEmpty()) {
            total.add(current);
        }

        // Transform into proper sections.
        ArrayList<MappedSection> sections = new ArrayList<>();
        for (ArrayList<RawChunk> chunks : total) {
            // Set up our section based on the first chunk.
            MappedSection currentSection = new MappedSection(chunks.getFirst());

            for (RawChunk currentChunk : chunks) {
                currentSection.addChunk(currentChunk);
            }

            sections.add(currentSection);
        }

        return sections;
    }
}
