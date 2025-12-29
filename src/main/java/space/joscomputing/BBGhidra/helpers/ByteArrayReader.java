package space.joscomputing.BBGhidra.helpers;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import java.io.IOException;

/** A combination of {@link BinaryReader} and {@link ByteArrayProvider}. */
public class ByteArrayReader extends BinaryReader {

    /** Creates a little-endian {@link BinaryReader} around the given array. */
    public ByteArrayReader(byte[] contents) {
        super(new ByteArrayProvider(contents), true);
    }

    /** Reads a string until end-of-stream, or until a null terminator. */
    public String readNextAsciiStringToEnd() {
        // This is really hacky. I apologize.
        StringBuilder result = new StringBuilder();
        try {
            while (true) {
                byte next = this.readNextByte();
                if (next == 0x00) {
                    break;
                }

                result.append((char) next);
            }
        } catch (IOException e) {
            // We'll assume we've hit the end of our reader.
        }

        return result.toString();
    }

    /** Reads a fixed-size array of unsigned integers. */
    public long[] readNextUnsignedIntArray(int nElements) throws IOException {
        long[] result = new long[nElements];
        for (int i = 0; i < nElements; i++) {
            result[i] = this.readNextUnsignedInt();
        }
        return result;
    }
}
