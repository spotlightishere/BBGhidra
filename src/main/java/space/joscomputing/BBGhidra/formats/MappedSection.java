package space.joscomputing.BBGhidra.formats;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import org.tukaani.xz.ArrayCache;
import org.tukaani.xz.LZMAInputStream;

/** A distinct range of chunks within a logical sequence. */
public class MappedSection {
    /** A stream of compressed contents, ready for consumption. */
    private final ByteArrayOutputStream lzmaContents = new ByteArrayOutputStream();

    /** Our raw contents of this section, proceeding LZMA content. */
    private final ByteArrayOutputStream rawContents = new ByteArrayOutputStream();

    /** The base address of this section. */
    private final long baseAddress;

    /** The type of this section, corresponding to {@link RawChunkFlags}. */
    private final int sectionType;

    /** Whether this section should be interpreted as unmapped. */
    private final boolean isUninitialized;

    /** Creates metadata for a mapped section based off the first available chunk. */
    public MappedSection(RawChunk firstChunk) {
        // Determine our type based on the first chunk available.
        sectionType = firstChunk.sectionType();
        baseAddress = firstChunk.loadAddress();
        isUninitialized = firstChunk.isUninitialized();
    }

    public void addChunk(RawChunk chunk) throws IOException {
        // Ensure other chunks are also this type.
        boolean isSection = (chunk.flags() & sectionType) == sectionType;
        if (!isSection) {
            throw new IOException("Inconsistent chunk type in sequence!");
        }

        if (chunk.isUninitialized() && lzmaContents.size() != 0) {
            // We should never have an uninitialized chunk present within a compressed section.
            throw new IOException("Uninitialized chunk type in compressed section!");
        }

        if (chunk.isCompressed() && this.isUninitialized) {
            // Similarly, no compressed chunks should be present in an unmapped section.
            throw new IOException("Compressed chunk type in uninitialized sequence!");
        }

        if (chunk.isCompressed()) {
            lzmaContents.writeBytes(chunk.payload());
        } else {
            rawContents.writeBytes(chunk.payload());
        }
    }

    /** Returns the base mapping address for this section. */
    public long getBaseAddress() {
        return this.baseAddress;
    }

    /** Returns whether this represents an uninitialized section. */
    public boolean isUninitialized() {
        return this.isUninitialized;
    }

    /**
     * The streams embedded within this format are LZMA1, also known as "LZMA Alone". Within its 13-byte header, a
     * 64-bit uncompressed size exists. <br>
     * Unlike the normal LZMA file format, these streams use those 8 bytes to store their compressed and uncompressed
     * size as 32-bit fields.
     *
     * @return The custom input stream reader with a correct size.
     */
    private LZMAInputStream getLzmaStream() throws IOException {
        // This is more or less an edit of the default LZMAInputStream constructor.
        byte[] totalCompressed = lzmaContents.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(totalCompressed);

        // First, read our properties byte (lc, lp, and pb).
        byte propsByte = (byte) inputStream.read();

        // Our dictionary size is an unsigned 32-bit little endian integer.
        int dictSize = 0;
        for (int i = 0; i < 4; ++i) dictSize |= inputStream.read() << (8 * i);

        // Here begins our modifications. Our next value is our compressed
        // size as a 32-bit little endian integer.
        int compressedSize = 0;
        for (int i = 0; i < 4; ++i) compressedSize |= inputStream.read() << (8 * i);

        // Next, we have our uncompressed size as a 32-bit little endian integer.
        long uncompSize = 0;
        for (int i = 0; i < 4; ++i) uncompSize |= (long) inputStream.read() << (8 * i);

        // Create a default ArrayCache for use.
        ArrayCache cache = ArrayCache.getDefaultCache();

        return new LZMAInputStream(inputStream, uncompSize, propsByte, dictSize, null, cache);
    }

    /** Decompresses the internal LZMA stream. */
    public byte[] decompress() throws IOException {
        if (lzmaContents.toByteArray().length == 0) {
            return new byte[] {};
        }

        // TODO: This is a hack due to some LZMA chunks
        // not having full LZMA data present.
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        try (LZMAInputStream inputStream = this.getLzmaStream()) {
            while (true) {
                int result = inputStream.read();
                if (result < 0) {
                    // We've exhausted our input stream.
                    break;
                }
                stream.write(result);
            }
            return stream.toByteArray();
        } catch (EOFException e) {
            // Return what we can.
            return stream.toByteArray();
        }
    }

    /** Returns the entire contents of this mapped section. * */
    public byte[] getContents() throws IOException {
        ByteArrayOutputStream totalContents = new ByteArrayOutputStream();
        // First, write raw contents.
        totalContents.writeBytes(rawContents.toByteArray());
        // Secondly, write decompressed contents.
        byte[] decompressed = this.decompress();
        totalContents.writeBytes(decompressed);
        return totalContents.toByteArray();
    }
}
