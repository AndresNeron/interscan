#!/bin/bash

start_cronometer() {
    start_time=$(date +%s.%N)
	#echo -e "Starting cronometer at:	${orangeColour}$start_time${endColour}"
	#echo
}

stop_cronometer() {
    stop_time=$(date +%s.%N)

    # Calculate the elapsed time in seconds with nanosecond precision
    elapsed_time=$(echo "$stop_time - $start_time" | bc)

    # Format the elapsed time for display
    formatted_time=$(printf "%.2f" "$elapsed_time")

    # Print the elapsed time
	echo
    echo -e "${orangeColour}Elapsed time: ${formatted_time} seconds${endColour}"

	final_time="$formatted_time"
}

