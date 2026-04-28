package space.joscomputing.BBGhidra.formats;

/**
 * A representation of an individual chunk.
 *
 * @param flags The raw flags set on this chunk.
 * @param loadAddress The intended load address for this chunk.
 * @param payload The internal payload of this chunk. For uninitialized chunks, this may be empty.
 */
public record RawChunk(int flags, long loadAddress, byte[] payload) {
    /** Whether this chunk's flags indicate it as uninitialized. */
    public boolean isUninitialized() {
        return (flags & RawChunkFlags.NO_DATA) == RawChunkFlags.NO_DATA;
    }

    /** Whether this chunk's flags indicate it as compressed. */
    public boolean isCompressed() {
        return (flags & RawChunkFlags.COMPRESSED_DATA) == RawChunkFlags.COMPRESSED_DATA;
    }

    /** The section this chunk represents. */
    public int sectionType() {
        return flags & ~(RawChunkFlags.COMPRESSED_DATA | RawChunkFlags.NO_DATA);
    }

    /** The length of this chunk's payload. */
    public int payloadSize() {
        return payload.length;
    }
}
