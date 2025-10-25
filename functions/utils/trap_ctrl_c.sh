#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

trap ctrl_c INT

ctrl_c() {
	echo -e "\n${grayColour}Received Ctrl+C, cleaning up...${endColour}"
    echo -e "\n${grayColour}[!] Exiting...\n${endColour}"
    tput cnorm; 
    exit 1
}
