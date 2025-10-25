#!/bin/bash

# This function receive a list of IP's and splits it into different random subsets
# with a certain predefined size.
# Example use:
# subnet ips.txt 8 "$extension_name"


#source "../../functions/resolvers/split_file.sh"

subnet (){
	ips_path="$1"
	subnet_size="$2"
	extension_name="$3"

	total_lines=$(wc -l "$ips_path" | cut -d ' ' -f1)

	echo "$total_lines"

	number_subnets=$((total_lines / subnet_size))

	printf "[%s] subnets with [%s] each one." "$number_subnets" "$subnet_size"

	prove=$((number_subnets * subnet_size))
	printf "\n%s x %s = %s" "$number_subnets" "$subnet_size" "$prove"

	shuf "$ips_path" > "$extension_name"

	split_file "$extension_name" "$number_subnets" "$extension_name"

	rm "$extension_name"

}
