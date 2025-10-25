#!/bin/bash

# Receives new path
change_Path() {
	default_path=$1
	if [ ! -d "$default_path" ]; then
		mkdir -p $default_path
	fi

	default_path2="$default_path/targets"
	if [ ! -d "$default_path2" ]; then
		mkdir -p $default_path2
	fi
}
