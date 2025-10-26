#!/bin/bash

# This code if for tracing the network topology and discovering routes to public IP's.
trace() {
	
	start_cronometer

	ips_path="$1"
	max_siblings="$2"

	echo -e "${orangeColour}\n[!] Tracing the next IP's...\n${endColour}"

	# Setup different 10.x.x.y uniq ranges
	bname=$(basename "$ips_path")
	subs_path="${default_path}/temp/${bname}"
	cut -d '.' -f1,2,3 "$ips_path" | uniq | sort -V > "$subs_path"

	temp_ips="${default_path}/temp/${bname}_ips"
	cont=1
	while IFS= read -r subs; do
		#echo "$subs"
		grep "$subs" "$ips_path" > "${temp_ips}.1"
		head -n "$max_siblings" "${temp_ips}.1" > "${temp_ips}.2"

		# While inside a while
		while IFS= read -r ip; do
			printf "${grayColour}\n[%s] %s\n${endColour}" "$cont" "$ip"
			result_path="${default_path}/traces2/${ip}"

			# Routing commands

			#traceroute -m 5 -p 23 "$ip"
			#traceroute -m 5 -T -p 23 "$ip"

			#hping3 -S -p 23 --traceroute --tr-stop -V "$ip"
			
			if [ ! -e "$result_path" ]; then
				hping3 -S -c 5 -p 23 --traceroute --tr-stop -V "$ip" | tee "$result_path" &
				sleep 0.5
			else
				printf "${orangeColour}[!] Trace already save it.${endColour}\n"

			fi

			#hping3 -S -i u1000 -p 23 --traceroute -V "$ip"
			#hping3 -S -p 80 --traceroute -V "$ip"
			#hping3 -S -p 7547 --traceroute -V "$ip"

			#hping3 -1 --traceroute --tr-stop -V "$ip" # ICMP

			
			((cont += 1))


		done < "${temp_ips}.2"

		#((cont += 1))

	done < "$subs_path" 

	stop_cronometer

	# Analyze the saved data.
	#cat traces2/* | grep from | cut -d ' ' -f7 | sort -V | uniq | sed 's/ip=//g' > victims/trace_ips


}

cont=1

hping3_file(){

	orangeColour="\e[0;32m\033[1m"
	grayColour="\e[0;31m\033[1m"
	endColour="\033[0m"

	default_path=$(pwd)
	bname_path="traces2"

	ip="$1"

	printf "${grayColour}\n[%s] %s\n${endColour}" "$cont" "$ip"
	result_path="${default_path}/${bname_path}/${ip}"

	# Routing commands
	if [ ! -e "$result_path" ]; then
		hping3 -S -c 5 -p 23 --traceroute --tr-stop -V "$ip" | tee "$result_path"
	else
		printf "${orangeColour}[!] Trace already save it.${endColour}\n"
	fi

	((cont += 1))

}

export -f hping3_file # Export the function

trace_parallel(){

	ips_path="$1"
	max_siblings="$2"

	start_cronometer

	echo -e "${orangeColour}\n[!] Tracing the next IP's...\n${endColour}"


	# Setup different 10.x.x.y uniq ranges
	bname=$(basename "$ips_path")
	subs_path="${default_path}/temp/${bname}"
	cut -d '.' -f1,2,3 "$ips_path" | uniq | sort -V > "$subs_path"

	temp_ips="${default_path}/temp/${bname}"
	hping_args="${temp_ips}_total"
	rm  "$hping_args" 2>/dev/null

	cp "$ips_path" "$hping_args"

	# Fill 'hping_args' with IP's
	#while IFS= read -r subs; do
	#	grep -m "$max_siblings" "$subs" "$ips_path" | tee -a "$hping_args"
		#grep -m "$max_siblings" "$subs" "$ips_path" >> "$hping_args"
	#done < "$subs_path" 

	wc -l "$hping_args"
	echo

	split_file "$hping_args" "$max_xterms" "${hping_args}."

	parallel -j "$max_xterms" hping3_file :::: "$hping_args"

	stop_cronometer

	# Analyze the saved data.
	#cat traces/* | grep from | cut -d ' ' -f7 | sort -V | uniq | sed 's/ip=//g' > victims/trace_ips

}
