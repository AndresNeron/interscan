#!/bin/bash

# This script automates the fetching of htmls using a list of http servers
# for classifying purposes

# ANSI color codes
BLACK=$'\e[0;30m'
RED=$'\e[0;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[1;33m'
BLUE=$'\e[0;34m'
PURPLE=$'\e[0;35m'
CYAN=$'\e[0;36m'
WHITE=$'\e[1;37m'
ORANGE=$'\e[0;33m'
GRAY=$'\e[1;30m'
LIGHT_RED=$'\e[1;31m'
LIGHT_GREEN=$'\e[1;32m'
LIGHT_BLUE=$'\e[1;34m'
LIGHT_PURPLE=$'\e[1;35m'
LIGHT_CYAN=$'\e[1;36m'
LIGHT_GRAY=$'\e[0;37m'
NC=$'\e[0m'

is_integer() {
    local value="$1"
    if [[ "$value" =~ ^-?[0-9]+$ ]]; then
        echo "Valid integer: $value"
        return 0
    else
        echo "Invalid integer: $value"
        return 1
    fi
}

# Method for fetching the html content for a given list of IPs
#get_htmls() {
    set +m

	timeout="$1"
	delay="$2"
	IPS_LIST="$3"
	log_file="$4"

	# Validate arguments
	is_integer "$timeout" || exit 1
	is_integer "$delay" || exit 1
    [ ! -f "$IPS_LIST" ] && {
        echo "[x] Path to IPs doesn't exist. Set it correctly."
        return 1
    }

	[ ! -f "$(dirname $log_file)" ] && {
        echo "[x] Path to log_file parent doesn't exist. Set it correctly."
        return 1
    }

    cont=1
    while IFS= read -r ip; do
        echo -e "${YELLOW}[$cont]${WHITE} $ip${NC}"
        let cont+=1

        {
            response=$(curl -q --connect-timeout "$timeout" -m 5 -s "http://$ip")
            timestamp=$(date "+%Y-%m-%d %H:%M:%S")
            if echo "$response" | grep -q 'DOCTYPE html PUBLIC'; then
                echo "nginx,$ip,$timestamp" >> "$log_file"
            elif echo "$response" | grep -q 'Pragma'; then
                echo "huawei,$ip,$timestamp" >> "$log_file"
            else
                echo "unknown,$ip,$timestamp" >> "$log_file"
            fi

			sudo -u postgres psql -p5432 -d scan_private -c \
			"INSERT INTO web_classification (ip_address, server_type, timestamp) VALUES ('$ip', '$server', '$timestamp');"
		} &

        sleep "$delay"
    done < "$IPS_LIST"

    wait
#}
