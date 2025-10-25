#!/bin/bash

output_path="$1"
masscan_pid_file="/tmp/$(basename "$output_path").pid"
masscan_pid=$(cat "$masscan_pid_file")

echo "[*] Waiting masscan results to finish with pid $masscan_pid."

# Wait until the PID disappears
cont=1
while ps -p "$masscan_pid" > /dev/null 2>&1; do
    echo "[$cont] s"
    let cont+=1
    sleep 1
done

# Clean the results
echo "[*] Masscan completed. Cleaning results."
grep open "$output_path"* | cut -d ' ' -f3 | sort -V > "$output_path.clean"
sort -V -u -o "$output_path.clean" "$output_path.clean"

echo "$output_path.clean"
