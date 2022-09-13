#!/bin/bash

# This is a sample demo script which creates a kParser instance named
# "test_parser" for parsing bit offsets for five tuples of TCP-IP header,
# i.e. ipproto, ipv4 source address, ipv4 destination address, tcp source port,
# tcp destination port.

die()
{
	echo "error:$1"
	exit -1
}

ipcmd() {
# -j -p enables formatted json print in stdout
	echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
	./ip/ip -j -p "$@" || die "command \`$@\` failed."
	echo "---------------------------------------------------------------"
}

#Lookup table creation for checking next nodes
ipcmd parser create table name table.ip
ipcmd parser create table name table.ether

#Extraction definition per header. Values (addoff local offsets)
ipcmd parser create metadata-rule name md.ipv4.ttl	\
		type bit_offset						    	\
		md-off 0							        \
		addoff 64

ipcmd parser create metadata-rule name md.ipv4.ipproto_offset	\
		type bit_offset					    	            \
		md-off 2							                    \
		addoff 72

ipcmd parser create metadata-rule name md.ipv4.src_address_offset	\
		type bit_offset						                    \
		addoff 96						                        \
		md-off 4
ipcmd parser create metadata-rule name md.ipv4.dst_address_offset	\
		type bit_offset						                    \
		addoff 128						                        \
		md-off 6

ipcmd parser create metadata-rule name md.tcp.src_port	\
		type bit_offset						        \
		addoff 0						            \
		md-off 8

ipcmd parser create metadata-rule name md.tcp.dst_port	\
		type bit_offset						        \
		addoff 16						            \
		md-off 10

# Creates a metalist object to be associated with a parse node. 
ipcmd parser create metalist name mdl.ipv4	\
		md.rule md.ipv4.dst_address_offset	\
		md.rule md.ipv4.src_address_offset	\
		md.rule md.ipv4.ttl              	\
		md.rule md.ipv4.ipproto_offset

ipcmd parser create metalist name mdl.tcp	\
		md.rule md.tcp.src_port				\
		md.rule md.tcp.dst_port

# Creates a parse nodes. Contains header size and how to calculate next header
ipcmd parser create node name node.ether	\
		min-hdr-length 14					\
		nxt.field-off 12					\
		nxt.field-len 2						\
		nxt.table table.ether

ipcmd parser create node name node.ipv4		\
		min-hdr-length 20 					\
		nxt.field-off 9						\
		nxt.field-len 1						\
		nxt.table table.ip					\
		metalist mdl.ipv4

ipcmd parser create node name node.tcp	\
		min-hdr-length 20				\
		metalist mdl.tcp

# Populate lookup tables.
ipcmd parser create table/table.ether	\
		key 0x800						\
		node node.ipv4

ipcmd parser create table/table.ip	\
		key 0x6						\
		node node.tcp

# Creates a parser object and specifies starting node
ipcmd parser create parser name test_parser	\
		metametasize 16						\
		rootnode node.ether