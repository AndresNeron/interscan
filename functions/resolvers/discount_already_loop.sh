#!/bin/bash

# The intention of this script is to serve for fetching
# a shorter list of already looped IPs.

minus_ips() {
    first_list="$1"
    second_list="$2"

    # Check if filename ends with _NUMBER
    if [[ "$first_list" =~ _(.*)$ ]]; then
        base="${first_list%_*}"        # Everything before last underscore
        number="${first_list##*_}"      # Everything after last underscore

        # Check if number is really an integer
        if [[ "$number" =~ ^[0-9]+$ ]]; then
            next_number=$((number + 1))
            resultant_list="${base}_${next_number}"
        else
            # Not a real number, treat as base without increment
            resultant_list="${first_list}_2"
        fi
    else
        # No underscore number found, append _2
        resultant_list="${first_list}_2"
    fi

	echo "[!]\t$resultant_list"

    # Subtract IPs
    grep -Fxv -f "$second_list" "$first_list" > "$resultant_list"
}
