#!/bin/bash

masscan_background(){
	TERM=xterm-256color
	threads="$1"
	ranges="$2"
	port_number="$3"
	rate="$4"
	scans_path="$default_path/scans"
	logs_path="$scans_path/logs"

	[ ! -d "$scans_path/crawling" ] && mkdir -p "$scans_path"
	[ ! -d "$logs_path" ] && mkdir -p "$logs_path"

	modified_ranges="${ranges//\//_}" # Substitute / with _
	modified_ranges="${modified_ranges//,/-}" # Substitute , with _

	cd "$default_path" || return 1
	start_cronometer


	# Update the last_number variable
	last_scan=$(find "$scans_path/crawling" -type f | grep -vE 'clean|join|paused' \
		| grep "ips_up_port_${port_number}_${modified_ranges}" | sort -V | tail -n 1)

	last_number=$(echo "Last Scan: $last_scan" | awk -F. '{print $NF}')

	# Update last_number
	if [[ ! "$last_number" =~ ^-?[0-9]+$ ]]; then
		echo -e "\n[!] This is the first scan and this port and range!"
		last_number=1
	else
		((last_number += 1))
	fi

	echo -e "\nNext Scan: $last_number"

	#return 1


	# Excluding ranges
	excluded_path="$scans_path/excluded_ranges"
cat << EOF > "$excluded_path"
#0.0.0.0/8
#10.0.0.0/8
127.0.0.0/8
169.254.0.0/16
#172.16.0.0/12
#192.168.0.0/16
#192.0.0.0/24
#192.0.2.0/24
192.88.99.0/24
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
144.0.0.0/8
EOF

	# Setup missing parameters for masscan
	conf="$scans_path/mass_port_${port_number}.conf"
	[ -e "$conf" ] && rm "$conf"

cat << EOF > "$conf"
# Targets
range = $ranges
ports = $port_number
rate = $rate
seed = 12345
randomize-hosts = true

# Exclude file
exclude-file = $excluded_path
EOF


	# Setup paths correctly
	bname="ips_up_port_${port_number}_${modified_ranges}"
	directory="$scans_path/crawling/$bname"
	mkdir -p "$directory"

	out_path_template="$directory/$bname"


	printf "\n${grayColour}[!] Configuration file: %s\n${endColour}" "$conf"
	cat "$conf"
	echo

	# Divide in cases based on shards
	printf "\n${grayColour}[!] Executed command:\n${endColour}"
	echo
	if [ "$threads" = '1/1' ]; then

		output_path="$out_path_template.${last_number}"
		mass_log=$(basename "$output_path")

		echo "sudo masscan -c $conf -oG $output_path | tee ${logs_path}/${mass_log}.log 2>${logs_path}/${mass_log}_errors.log"

		printf "\n${grayColour}[!] Running masscan on port $port_number in the background:${endColour}\n\n"
		sudo masscan -c "$conf" -oG "$output_path" | tee "${logs_path}/${mass_log}.log" 2>"${logs_path}/${mass_log}_errors.log"

		printf "\n${grayColour}[!] Waiting the masscan jobs to finish...${endColour}"
		wait
		stop_cronometer

		# Extract the ips from the masscan above and save the results
		grep open "$output_path"* | cut -d ' ' -f3 | sort -V > "$output_path.clean"
		sort -V -u -o "$output_path.clean" "$output_path.clean"

	else

		numerator=$(echo "$threads" | cut -d '/' -f1)
		denominator=$(echo "$threads" | cut -d '/' -f2)
		output_path="${out_path_template}@${numerator}@${denominator}.${last_number}"
		mass_log=$(basename "$output_path")
		touch "${output_path}"

		#echo -e "nohup sudo masscan -c $conf --shard $threads -oG $output_path 2>&1 | stdbuf -oL tee -a ${logs_path}/${mass_log}.log &"
		#echo

		#printf "\n${grayColour}[!] Running masscan on port $port_number in the background:${endColour}\n\n"
		#nohup sudo masscan -c "$conf" --shard "$threads" -oG "$output_path" 2>&1 | stdbuf -oL tee -a "${logs_path}/${mass_log}.log" &

		echo -e "nohup sudo -n masscan -c \"$conf\" --shard \"$threads\" -oG \"$output_path\" > \"${logs_path}/${mass_log}.log\" 2> \"${logs_path}/${mass_log}_errors.log\" < /dev/null & disown"
		nohup sudo -n masscan -c "$conf" --shard "$threads" -oG "$output_path" \
		  > "${logs_path}/${mass_log}.log" 2> "${logs_path}/${mass_log}_errors.log" < /dev/null & disown
		echo

		# Store the associated masscan pid into a file
		masscan_pid=$!
		masscan_pid_file="/tmp/$(basename $output_path).pid"
		echo -e "\n${grayColour}[*] Masscan launched with PID $masscan_pid and saved into\n$masscan_pid_file ${endColour}"
		echo "$masscan_pid" > "$masscan_pid_file"

	fi


	# Perform the join of the know IP's
	#grep open "$out_path_template"* | cut -d ' ' -f3 | sort -V > "${output_path}.join"
	#sort -V -u -o "$output_path.join" "$output_path.join"

	# This line is for importing the results into the PostgreSQL database
	#import_masscan_results "$output_path" 10

}

import_masscan_results(){

	default_path_pynet="$default_path/pynet"
	output_path="$1"
	threads="$2"
	
	# Setup the python environment
	cd "$default_path_pynet" || return 1
	source "telEnv/bin/activate" || return 1
	source "exports.sh"

	printf "\n[!] Loading results into the database.\n"
	python3 main_scripts/save_masscan_results.py -iL "$output_path" -t "$threads"

	deactivate
	
}
