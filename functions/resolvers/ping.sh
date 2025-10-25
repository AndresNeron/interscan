#!/bin/bash

# This script pings the list of IPs from a file
# and returns which of those are up.
# It is implemented using parallel coroutines.


# Function to check if an IP is up
check_ip() {
    local ip="$1"
    local result

    # Ping the IP once and capture the result
    result=$(ping -c 1 "$ip" 2>/dev/null | grep ' 0% packet loss')

    # If the result is not empty, print that the IP is up
    if [ -n "$result" ]; then
		printf "[Up] %s\n" "$ip"
		((cont++))
    fi
}

# Explicitly export the check_ip function
export -f check_ip # This will be called with parallel

ping_parallel() {
    ips_path="$1"
    threads="$2"

    start_cronometer

    # Use parallel to ping IPs concurrently
    parallel -j "$threads" check_ip < "$ips_path"

    stop_cronometer
}
