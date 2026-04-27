#!/bin/bash

TARGET_DIR="${1:-.}"
OUTPUT_FILE="out.txt"

if [ ! -d "$TARGET_DIR" ]; then
  echo "Error: '$TARGET_DIR' is not a valid directory."
  exit 1
fi

# Clear/create the output file
echo "Directory dump: $TARGET_DIR" > "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Find all files recursively, sorted
find "$TARGET_DIR" -type f | sort | while read -r file; do
  # Skip the output file itself
  [ "$(realpath "$file")" = "$(realpath "$OUTPUT_FILE")" ] && continue

  echo "================================================================" >> "$OUTPUT_FILE"
  echo "FILE: $file" >> "$OUTPUT_FILE"
  echo "================================================================" >> "$OUTPUT_FILE"

  # Check if the file is readable text
  if file "$file" | grep -qE 'text|empty|ASCII|UTF'; then
    cat "$file" >> "$OUTPUT_FILE"
  else
    echo "[binary or unreadable file — skipped]" >> "$OUTPUT_FILE"
  fi

  echo "" >> "$OUTPUT_FILE"
done

echo "Done! Output written to $OUTPUT_FILE"
