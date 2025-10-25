#!/bin/bash


helpPanel(){
	for i in $(seq 1 65); do echo -ne "${greenColour}-"; done; echo -ne ${endColour}
	echo -e "\n${purpleColour}This program automates attacks on telnet 23 and ssh 22.${endColour}" 
	for i in $(seq 1 65); do echo -ne "${greenColour}-"; done; echo -ne ${endColour}
	echo -e "\n${turquoiseColour} [!] Usage:${endColour} ${orangeColour}./interscan.sh [options] ${endColour}"
	for i in $(seq 1 65); do echo -ne "${greenColour}-"; done; echo -ne ${endColour}
	echo -e "\n\t${orangeColour}-i\t--ips\t\t${endColour}${turquoiseColour} Receive ips to process.${endColour}"
	echo -e "\t${orangeColour}-r\t--ranges\t${endColour}${turquoiseColour} Receive ranges in CIDR format separated by comma.${endColour}"
	echo -e "\t${orangeColour}-p\t--port\t\t${endColour}${turquoiseColour} Specify desired port, by default 23.${endColour}"
	echo -e "\t${orangeColour}-t\t--threads\t${endColour}${turquoiseColour} The number of threads in parallel.${endColour}"
	echo -e "\t${orangeColour}-g\t--ping\t\t${endColour}${turquoiseColour} Ping discovery.${endColour}"
	echo -e "\t${orangeColour}-l\t--login\t\t${endColour}${turquoiseColour} Simply log in using a interscan connection.${endColour}"
	echo -e "\t${orangeColour}-f\t--ifconfig\t${endColour}${turquoiseColour} Send 'ifconfig' command thorugh a interscan connection.${endColour}"
	echo -e "\t${orangeColour}-n\t--ssid\t\t${endColour}${turquoiseColour} Obtain the SSID name of each device.${endColour}"
	echo -e "\t${orangeColour}-m\t--masscan\t${endColour}${turquoiseColour} Scan the list of provided ips in telnet port 23.${endColour}"
	echo -e "\t${orangeColour}-s\t--massrate\t${endColour}${turquoiseColour} Change the rate for the each masscan thread, default 1000.${endColour}"
	echo -e "\t${orangeColour}-e\t--exclude\t${endColour}${turquoiseColour} Provide a list of IP ranges to exclude. By default 'scans/excluded_ranges'.${endColour}"
	echo -e "\t${orangeColour}-d\t--trace\t\t${endColour}${turquoiseColour} Trace the network topology of a list of ips.${endColour}"
	echo -e "\t${orangeColour}-j\t--javat\t\t${endColour}${turquoiseColour} Perform the logins using java instead of python.${endColour}"
	echo -e "\t${orangeColour}-a\t--nmap\t\t${endColour}${turquoiseColour} After determining the open ports with masscan, determine the running services.${endColour}"

	echo -e "\t${orangeColour}-h\t--help\t\t${endColour}${turquoiseColour} Show this help message${endColour}${turquoiseColour}  ${endColour}"
	echo -e "\n\t${orangeColour}Examples:\t${endColour}"
	echo -e "\t [1] ${turquoiseColour}./interscan.sh${endColour}${orangeColour} -i ${endColour}${greenColour}victims${endColour}${orangeColour} -t ${endColour}10${orangeColour} --ifconfig${endColour}"
	echo -e "\t [2] ${turquoiseColour}./interscan.sh${endColour}${orangeColour} -i ${endColour}${greenColour}victims${endColour}${orangeColour} -t ${endColour}10${orangeColour} --login${endColour}"
	echo -e "\t [2] ${turquoiseColour}./interscan.sh${endColour}${orangeColour} -i ${endColour}${greenColour}victims${endColour}${orangeColour} -t ${endColour}10${orangeColour} --ssid${endColour}"
	echo -e "\t [3] ${turquoiseColour}./interscan.sh${endColour}${orangeColour} -i ${endColour}${greenColour}victims${endColour}${orangeColour} -t ${endColour}10${orangeColour} --ping${endColour}"
	echo -e "\t [4] ${turquoiseColour}sudo ./interscan.sh${endColour}${orangeColour} -r ${endColour}${greenColour}10.0.0.0/8${endColour}${orangeColour} -p ${endColour}23${orangeColour} -t ${endColour}'1/10'${orangeColour} -m${endColour}${orangeColour} -e ${endColour}scans/excluded_ranges"
	echo -e "\t [5] ${turquoiseColour}sudo ./interscan.sh${endColour}${orangeColour} -r ${endColour}${greenColour}10.0.0.0/8${endColour}${orangeColour} -p ${endColour}23${orangeColour} -t ${endColour}'1/1'${orangeColour} -s ${endColour}100${orangeColour} -m${endColour}"
	echo -e "\t [6] ${turquoiseColour}./interscan.sh${endColour}${orangeColour} -i ${endColour}${greenColour}victims${endColour}${orangeColour} -t ${endColour}10${orangeColour} --trace${endColour}"
	echo -e "\t [7] ${turquoiseColour}./interscan.sh${endColour}${orangeColour} -i ${endColour}${greenColour}victims${endColour}${orangeColour} -t ${endColour}10${orangeColour} --javat${endColour}"

	echo -e "\n\t${orangeColour}Notes:\t${endColour}"
	echo -e "\t [1]\t${turquoiseColour} This command discover hosts up using ping in parallel.${endColour}"
	echo -e "\t [2]\t${turquoiseColour} This command try to login with each IP in 10 telnet threads connections.${endColour}"
	echo -e "\t [2]\t${turquoiseColour} This command try to determine SSID name of each IP in 10 telnet threads connections.${endColour}"
	echo -e "\t [3]\t${turquoiseColour} This command execute 'ifconfig' in 10 telnet threads connections.${endColour}"
	echo -e "\t [4]\t${turquoiseColour} This command discover active telnet hosts using masscan subdiving with shards.${endColour}"
	echo -e "\t [5]\t${turquoiseColour} This command discover active telnet hosts using masscan subdiving in shards, specifying the rate of masscan.${endColour}"
	echo -e "\t [6]\t${turquoiseColour} This command discover and trace the hops of the provided list of IP's.${endColour}"
	echo -e "\t [7]\t${turquoiseColour} This command try to log with each IP in 10 telnet threads connections, similar to example [2], but using Java.${endColour}"
	exit 0
}
