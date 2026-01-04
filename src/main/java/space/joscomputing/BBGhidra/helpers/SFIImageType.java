package space.joscomputing.BBGhidra.helpers;

/** Distinct image components within an SFI. */
public enum SFIImageType {
    /** Modem firmware, running on an ARMv4t core. */
    MODEM("Modem", "ARM:LE:32:v4"),

    /** Application/OEM firmware, running on an ARMv6t core. */
    APP("App", "ARM:LE:32:v6");

    private final String displayName;
    private final String languageId;

    /**
     * A possible image type within an SFI.
     *
     * @param displayName The human-readable display name of this type.
     * @param languageId The language ID to inform Ghidra.
     */
    SFIImageType(String displayName, String languageId) {
        this.displayName = displayName;
        this.languageId = languageId;
    }

    /** Metadata property set to distinguish the firmware type represented. */
    public static final String IMAGE_TYPE_PROPERTY = "BlackBerry Image Type";

    /** Returns the filename to reference this with (e.g. `app.bin` or `modem.bin`). */
    public final String getImageFilename() {
        String enumCase = this.toString().toLowerCase();
        return String.format("%s.bin", enumCase);
    }

    /** Returns the supported language ID for this image type. */
    public String getLanguageId() {
        return languageId;
    }

    /** Used when displaying the property value in Ghidra. */
    public String toString() {
        return this.displayName;
    }
}
