#!/bin/bash

# Define the pingo function
pingo() {
    ping "$1" | while read pingu; do
        echo "[$(date)] $pingu"
    done
}
