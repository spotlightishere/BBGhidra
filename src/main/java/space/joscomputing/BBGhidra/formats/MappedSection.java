package space.joscomputing.BBGhidra.formats;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import org.tukaani.xz.ArrayCache;
import org.tukaani.xz.LZMAInputStream;

/** A distinct range of chunks within a logical segment in a LZMA mapping. */
public class MappedSection {
    /** Any chunk, whether uninitialized, or compressed. */
    private record MappedChunk(long loadAddress, long segmentSize) {}

    private final ArrayList<MappedChunk> uninitialized = new ArrayList<>();
    private Long compressedBaseAddress;
    private final ByteArrayOutputStream contents = new ByteArrayOutputStream();

    public void addUninitializedChunk(long loadAddress, long chunkSize) {
        MappedChunk current = new MappedChunk(loadAddress, chunkSize);
        uninitialized.add(current);
    }

    public void addCompressedChunk(long loadAddress, byte[] payload) throws IOException {
        // TODO: We don't retain information about compressed chunks.
        // We (perhaps naively) assume that all compressed chunks are sequential.
        if (compressedBaseAddress == null) {
            compressedBaseAddress = loadAddress;
        }

        contents.write(payload);
    }

    public long getCompressedBaseAddress() {
        return compressedBaseAddress;
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
        byte[] totalCompressed = contents.toByteArray();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(totalCompressed);

        // First, read our properties byte (lc, lp, and pb).
        byte propsByte = (byte) inputStream.read();

        // Our dictionary size is an unsigned 32-bit little endian integer.
        int dictSize = 0;
        for (int i = 0; i < 4; ++i) dictSize |= inputStream.read() << (8 * i);

        // Here begins our modifications. Our next value is our compressed
        // size as a 32-bit little endian integer.
        // We have no way to compare against this, so we'll simply read past it.
        inputStream.skipNBytes(4);

        // Next, we have our uncompressed size as a 32-bit little endian integer.
        long uncompSize = 0;
        for (int i = 0; i < 4; ++i) uncompSize |= (long) inputStream.read() << (8 * i);

        // Create a default ArrayCache for use.
        ArrayCache cache = ArrayCache.getDefaultCache();

        return new LZMAInputStream(inputStream, uncompSize, propsByte, dictSize, null, cache);
    }

    /** Decompresses the internal LZMA stream. */
    public byte[] decompress() throws IOException {
        try (LZMAInputStream inputStream = this.getLzmaStream()) {
            return inputStream.readAllBytes();
        }
    }
}
