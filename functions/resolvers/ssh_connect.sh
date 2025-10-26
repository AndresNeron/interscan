#!/bin/bash

# This function is to connecting to the server using ssh
ssh_connect (){
	router_ip="$1"
	public_key="~/.ssh/id_rsa.pub"
	private_key="~/.ssh/id_rsa"
	private_key_basename="id_rsa"

	# Copy the public key to the RouterOS MicroTik software
	scp "$public_key" admin@"$router_ip":/id_rsa.pub

	# Connect through ssh
	ssh -i "$private_key" admin@"$router_ip"

	# Import the public key
	/user ssh-keys import public-key-file=id_rsa.pub user=admin
}
