package space.joscomputing.BBGhidra.helpers;

/** Metadata for a segment we'll provide to Ghidra. */
public record SegmentInfo(long blockAddress, long blockSize, String segmentName) {}
