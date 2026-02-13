#!/bin/sh
# For Ubuntu/Debian: sudo apt-get install -y exfatprogs exfat-fuse fuse3 rsync
# Create a exFAT image from a directory
# Usage: mkexfat.sh <input_dir> [output_file]

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <input_dir> [output_file]"
    exit 1
fi

INPUT_DIR="$1"
OUTPUT="${2:-test.ffpkg}"

# Calculate required size (dir size + 20% overhead + 10MB slack)
BYTES=$(du -s -k "$INPUT_DIR" | awk '{print $1 * 1024}')
OVERHEAD=$((BYTES / 5))                 # 20%
SLACK=$((10 * 1024 * 1024))             # 10MB
TOTAL=$((BYTES + OVERHEAD + SLACK))

# Round up to nearest MB
MB=$(( (TOTAL + 1024*1024 - 1) / (1024*1024) ))

echo "Input size: $BYTES bytes"
echo "Image size: ${MB}MB"

truncate -s "${MB}M" "$OUTPUT"
mkfs.exfat -c 4K "$OUTPUT"
mkdir -p /mnt/exfat
mount -t exfat-fuse -o loop "$OUTPUT" /mnt/exfat
rsync -r --info=progress2 "$INPUT_DIR" /mnt/exfat/

umount /mnt/exfat

echo "Created $OUTPUT"
