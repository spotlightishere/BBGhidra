package space.joscomputing.BBGhidra.formats;

/** Flags assigned to chunks. */
public final class RawChunkFlags {
    /** This chunk refers to memory without data, perhaps simply mapped in or zeroed. */
    public static final int NO_DATA = 0x1;

    /** This chunk is third-party app data (e.g. non-Qualcomm RTOS). */
    public static final int APP_DATA = 0x10;

    /** This chunk is RTOS data. */
    public static final int OS_DATA = 0x20;

    /** This chunk is modem data. */
    public static final int MODEM_DATA = 0x200;

    /** This chunk is compressed. */
    public static final int COMPRESSED_DATA = 0x400;
}
