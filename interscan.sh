#!/bin/bash

# For writting more robust error-resistant code
# by enforcing stricter error handling and variable usage.
#set -euo pipefail

default_path="$(dirname "$(realpath "$0")")"

# Include function files
for file in "$default_path/functions/"*/*; do
    if [[ -f "$file" && "$file" != *clean_masscan* && \
          "$file" != *exclude_ips* && \
          "$file" != *get_html* && \
          "$file" != *pingo* ]]; then
        source "$file"
    fi
done

# Global Variables
TERM=xterm-256color
PORT="23" # Default port
RATE="1000"
excluded_ranges="$default_path/scans/excluded_ranges"
max_xterms_top=1000
max_xterms=1
shard='1/1'
[ -e "$IPs_PATH" ] && lines_global=$(wc -l < "$IPs_PATH")


# Main Code

counter=0
ARGS=$(getopt -o i:r:p:t:glfs:me:djh --long ips:,ranges:port:,threads:,ping,login,ifconfig,massrate:,masscan,exclude:,trace,javat,help -n "$0" -- "$@")
eval set -- "$ARGS"

while true; do
    case "$1" in
		-i|--ips)
            IPs_PATH="$2"
			[ ! -e "$IPs_PATH" ] && echo -e "${redColour}[#] Path for IPs no exist in the system. Set it correctly.${endColour}" && exit 1
            counter=$((counter + 1))
            shift 2
            ;;
		-r|--ranges)
            RANGES="$2"
			[ -z "$RANGES" ] && echo -e "${redColour}[#] Setup the IP ranges correctly.${endColour}" && exit 1

            counter=$((counter + 1))
            shift 2
            ;;
        -p|--port)
			PORT="$2"
			[ "$PORT" -lt "0" ] || [ "$PORT" -gt 65535 ] && echo -e "${redColour}[#] Port out of range.${endColour}" && exit 1

            counter=$((counter + 1))
            shift 2
            ;;
        -t|--threads)
			shard="$2"
			max_xterms=$(echo "$shard" | cut -d '/' -f2)

			[ "$max_xterms" -gt "$max_xterms_top" ] && printf "[#] Max number of threads %s exceed." "$max_xterms_top" && exit 1
			[ "$max_xterms" -lt "0" ] && printf "[#] Max number of threads %s is less than 0." "$max_xterms_top" && exit 1
			printf "\n${grayColour}[!] Threads: %s${endColour}\n" "$max_xterms"

            counter=$((counter + 1))
            shift 2
            ;;
        -g|--ping)
			printf "\n${grayColour}[!] Start pinging at: %s${endColour}\n" "$(date "+%Y-%m-%d %H:%M:%S")"
			ping_parallel "$IPs_PATH" "$max_xterms"

            counter=$((counter + 1))
            shift 1
            ;;
        -l|--login)
			printf "\n${grayColour}[!] Start the logins at: %s${endColour}\n" "$(date "+%Y-%m-%d %H:%M:%S")"
			parallel_pynet "-l True" # This tell simply login

            counter=$((counter + 1))
            shift 1
            ;;

        -f|--ifconfig)
			printf "\n${grayColour}[!] Paralleling: ifconfig${endColour}\n"
			parallel_pynet "-c ifconfig" # This tells to send the ifconfig command

            counter=$((counter + 1))
            shift 1
            ;;
        -s|--massrate)
			RATE="$2"
			[ "$RATE" -lt 0 ] && echo -e "${redColour}[#] Setup the rate for each masscan thread correctly.${endColour}" && exit 1
			echo -e "${orangeColour}[!] RATE per Thread: $RATE ${endColour}"

            counter=$((counter + 1))
            shift 2
            ;;
        -m|--masscan)
			[ -z "$RANGES" ] && echo -e "${redColour}[#] Setup the IP ranges correctly.${endColour}" && exit 1
			masscan_background "$shard" "$RANGES" "$PORT" "$RATE"

            counter=$((counter + 1))
            shift 1
            ;;
        -e|--excluded)
			excluded_ranges="$2"
			[ ! -e "$excluded_ranges" ] && echo -e "${redColour}[#] Excluded IP ranges file doesn't exist in the system. Set it up correctly.${endColour}" && exit 1

            counter=$((counter + 1))
            shift 2
            ;;
        -d|--trace)
			max_siblings=4

			#Call the function
			trace_parallel "$IPs_PATH" "$max_siblings"

            counter=$((counter + 1))
            shift 1
            ;;
        -j|--javat)
			
			#Call the function
			javat

            counter=$((counter + 1))
            shift 1
            ;;
        -h|--help)
			clear
            helpPanel
            ;;
        --)
            shift
            break
            ;;
        *)
            #helpPanel
            echo -e "\n${redColour}[!] Invalid option. Exiting...\n${endColour}"
            exit 1
            ;;
    esac
done

# Restore cursor and show help if no options were provided
tput cnorm
if [ "$counter" -eq 0 ]; then
    helpPanel
fi
