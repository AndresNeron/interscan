#!/bin/bash

file1="$1"
file2="$2"

# Ensure both files exist
if [[ ! -f "$file1" || ! -f "$file2" ]]; then
    echo "Usage: $0 <file1> <file2>"
    echo "Both files must exist and contain IPs line by line."
    exit 1
fi

# Generate the filtered content and overwrite file1 safely
temp_file=$(mktemp)

if ! grep -Fxv -f "$file2" "$file1" > "$temp_file"; then
    echo "Error: grep failed"
    exit 1
fi

# Move temp file over original (requires sudo if needed)
if ! mv "$temp_file" "$file1"; then
    echo "Error: Could not overwrite $file1 — trying with sudo"
    sudo mv "$temp_file" "$file1" || {
        echo "Failed to overwrite $file1 even with sudo."
        exit 1
    }
fi

echo "Successfully removed IPs from $file1"
