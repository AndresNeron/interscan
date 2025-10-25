#!/bin/bash

windows() {
	max_xterms="$1"
	limit=30
	if [ "$max_xterms" -gt 30 ]; then
		echo "The total number of windows cannot be greater than $limit"
	fi
}
