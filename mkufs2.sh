#!/bin/sh
# Create a PS4-compatible UFS2 image from a directory
# Usage: mkufs2.sh <input_dir> [output_file]

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <input_dir> [output_file]"
    exit 1
fi

INPUT_DIR="$1"
OUTPUT="${2:-download0.dat}"

if [ ! -d "$INPUT_DIR" ]; then
    echo "Error: input directory not found: $INPUT_DIR"
    exit 1
fi

if [ ! -f "$INPUT_DIR/eboot.bin" ]; then
    echo "Error: eboot.bin not found in source directory: $INPUT_DIR"
    exit 1
fi

# More accurate sizing for UFS2:
# - file payload rounded to fragment size (-f)
# - minimal per-directory allocation
# - inode table estimate
# - fixed filesystem metadata headroom
BLOCK_SIZE=32768
FRAG_SIZE=4096
MINFREE_PERCENT=0
BYTES_PER_INODE=262144
INODE_SIZE=256
INODE_SPARE=2048
META_FIXED=$((64 * 1024 * 1024))   # superblocks, cg metadata, allocator slack
MIN_SLACK=$((64 * 1024 * 1024))    # minimum copy/runtime safety margin
SPARE_MIN=$((64 * 1024 * 1024))    # lower bound for dynamic headroom
SPARE_MAX=$((512 * 1024 * 1024))   # upper bound for dynamic headroom

FILE_COUNT=$(find "$INPUT_DIR" -type f | wc -l | tr -d ' ')
DIR_COUNT=$(find "$INPUT_DIR" -type d | wc -l | tr -d ' ')
RAW_FILE_BYTES=$(find "$INPUT_DIR" -type f -exec stat -f '%z' {} + | \
  awk '{s += $1} END {print s + 0}')

AVG_FILE_BYTES=0
if [ "$FILE_COUNT" -gt 0 ]; then
    AVG_FILE_BYTES=$((RAW_FILE_BYTES / FILE_COUNT))
fi

# UFS profile selection:
# - large-file sets: 64K block
# - small/mixed-file sets: 32K block (safer/denser default)
if [ "$AVG_FILE_BYTES" -ge $((1024 * 1024)) ]; then
    BLOCK_SIZE=65536
fi

DATA_BYTES=$(find "$INPUT_DIR" -type f -exec stat -f '%z' {} + | \
  awk -v frag="$FRAG_SIZE" '{s += int(($1 + frag - 1) / frag) * frag} END {print s + 0}')
DIR_BYTES=$((DIR_COUNT * FRAG_SIZE))
INODE_COUNT=$((FILE_COUNT + DIR_COUNT + INODE_SPARE))
INODE_BYTES=$((INODE_COUNT * INODE_SIZE))

BASE_TOTAL=$((DATA_BYTES + DIR_BYTES + INODE_BYTES + META_FIXED))
SPARE_BYTES=$((BASE_TOTAL / 200))   # ~0.5%
if [ "$SPARE_BYTES" -lt "$SPARE_MIN" ]; then
    SPARE_BYTES=$SPARE_MIN
fi
if [ "$SPARE_BYTES" -gt "$SPARE_MAX" ]; then
    SPARE_BYTES=$SPARE_MAX
fi
TOTAL=$((BASE_TOTAL + SPARE_BYTES))
MIN_TOTAL=$((RAW_FILE_BYTES + MIN_SLACK))
if [ "$TOTAL" -lt "$MIN_TOTAL" ]; then
    TOTAL=$MIN_TOTAL
fi

# Round up to nearest MB
MB=$(( (TOTAL + 1024*1024 - 1) / (1024*1024) ))

echo "Input size (raw files): $RAW_FILE_BYTES bytes"
echo "Input size (UFS alloc): $DATA_BYTES bytes"
echo "Files: $FILE_COUNT, Dirs: $DIR_COUNT"
echo "UFS profile: -b $BLOCK_SIZE -f $FRAG_SIZE -m $MINFREE_PERCENT -i $BYTES_PER_INODE (avg file=$AVG_FILE_BYTES bytes)"
echo "Image size: ${MB}MB"

truncate -s "${MB}M" "$OUTPUT"

MD=$(mdconfig -a -t vnode -f "$(realpath "$OUTPUT")")
newfs -O 2 -b "$BLOCK_SIZE" -f "$FRAG_SIZE" -m "$MINFREE_PERCENT" -i "$BYTES_PER_INODE" /dev/${MD}

mkdir -p /mnt
mount /dev/${MD} /mnt

# Copy contents safely (includes hidden files)
tar -C "$INPUT_DIR" -cf - . | tar -C /mnt -xpf -

chmod -R 777 /mnt/*

umount /mnt
mdconfig -d -u ${MD}

echo "Created $OUTPUT"
