#!/bin/bash

parallel_pynet() {

	command="$1"
	#command='-l'

	start_cronometer
	
	# Necessary variables
	x_offset=0
	y_offset=0
	running_xterms=0
	xterm_counter=0

	width_const=6
	height_const=12

	width_max=1366
	#height_max=768

	window_width=50
	window_height=80

	columns=$((width_max / (window_width)))

	# Delete old files
	rm "${IPs_PATH}_"* 2>/dev/null
	rm temp/script* 2>/dev/null

	# Directory where will be located the splits
	split_file "$IPs_PATH" "$max_xterms" "${IPs_PATH}_"

	# Delete previous temp scripts

	# The command will be executed in parallel.
	xterm_counter=1
	for chunk_file in "${IPs_PATH}_"*; do
		echo "$chunk_file"

		# Make the correct operations to display successfully.
		x_offset=$((running_xterms % columns * (window_width * width_const)))
		cocient=$((x_offset / width_max))
		x_offset=$((x_offset - (cocient * width_max)))
		if ((x_offset < window_width * width_const)); then
			variance="$x_offset"
		fi
		x_offset=$((x_offset - variance))
		y_offset=$((cocient * window_height * height_const))


		# Bash script that will be executed.

		script_path="temp/script_${xterm_counter}"
cat << EOF > "$script_path"
#!/bin/bash

printf "\n[!] Inside the temp_script: %s\n\n" "$xterm_counter"

wc -l $chunk_file
echo

# This line is so important
source exports.sh
#python3 pynet/pynet.py -iL $chunk_file -p 23 -u root -pw adminHW -c ifconfig
python3 pynet/pynet.py -iL $chunk_file -p 23 -u root -pw adminHW $command

#for i in \$(seq 1 100); do
#	echo "\$i" 
#	sleep 1
#done
EOF


		# Execute the script in the background
		chmod +x "$script_path" 
		#echo "$script_path"
		#xterm -geometry ${window_width}x${window_height}+${x_offset}+${y_offset} -e "$script_path" &
		bash "$script_path" &
		sleep 2

		# Increment counters
		((xterm_counter++))
		((running_xterms++))

	done

	# This command kill all the xterm background processes
	#pgrep -f 'temp/script' | xargs kill

	wait

	stop_cronometer

}

