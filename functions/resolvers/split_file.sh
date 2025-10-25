#!/bin/bash

# This receives tree arguments.
split_file (){

    if [ "$#" -ne 3 ]; then
        echo "Usage: $0 <file_path> <number_of_splits> <output_format_path>"
		return 1
    fi

    # Receives the path of the IP's and the number of files to split
    ips_path="$1"
    number="$2"
	out_path="$3"

	# Split the files into $number number of chunks
	lines_global=$(wc -l < "$ips_path")

	split -d -l $((lines_global / (number))) "$ips_path" "${out_path}"
}
