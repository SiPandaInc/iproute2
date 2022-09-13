#!/bin/bash

# This is a sample demo script which creates a kParser instance named
# "test_parser" for parsing bit offsets for five tuples of TCP-IP header,
# i.e. ipproto, ipv4 source address, ipv4 destination address, tcp source port,
# tcp destination port.

die()
{
	echo "error: $@"
	exit -1
}

ipcmd() {
# -j -p enables formatted json print in stdout
	echo "Executing \`./ip/ip -j -p $@\`" | fold -w 80
	./ip/ip -j -p "$@" || die "command \`$@\` failed."
	echo "---------------------------------------------------------------"
}

# Creates a lookup table object named table.ip
# It is used to lookup ipproto (in this case only tcp).
# Entries of this table will be added later in this script.
ipcmd parser create table name table.ip

# Creates a lookup table object named table.ether
# It is used to lookup ethproto (in this case only IPv4).
# Entries of this table will be added later in this script.
ipcmd parser create table name table.ether

# This is a metadata extraction rule to derive the bit offset of ipproto field
# from packet and store in the user provided metadata buffer.
# `type bit_offset` specifies the operation type of this metadata is to derive
# the offset of the bit field from the packet.
# `doff 0` means the derived data will be written at byte destination offset 0
# in the user provided metadata buffer.
# `addoff 72` specifies the bit offset of the ipproto field relative to the
# beginning of the IPv4 header.
# Note that for `type bit_offset`, the metadata is always 2 bytes written to
# user specified metadata buffer.
# Value written to metadata buffer will be absolute bit offset of IPv4 header +
# addoff.
ipcmd parser create md-rule name md.ipproto_offset			\
		type bit_offset						\
		addoff 72						\
		doff 0

# This is a metadata extraction rule to derive the bit offset of source IPv4
# address.
ipcmd parser create md-rule name md.src_address_offset			\
		type bit_offset						\
		addoff 96						\
		doff 2

# This is a metadata extraction rule to derive the bit offset of destination
# IPv4 address.
ipcmd parser create md-rule name md.dst_address_offset			\
		type bit_offset						\
		addoff 128						\
		doff 4

# This is a metadata extraction rule to derive the bit offset of source TCP port
# `addoff 0` specifies the bit offset of the TCP source port relative to the
# beginning of the TCP header.
ipcmd parser create md-rule name md.tcp.src_port			\
		type bit_offset						\
		addoff 0						\
		doff 6

# This is a metadata extraction rule to derive the bit offset of destination
# TCP port.
ipcmd parser create md-rule name md.tcp.dst_port			\
		type bit_offset						\
		addoff 16						\
		doff 8

# Creates a metalist object identified by name "mdl.ipv4", which will later be
# associated with a parse node. 
# metalist is a collection of previously defined metadata extraction rules
# related to a specific protocol (IPv4 in this case).
ipcmd parser create metalist name mdl.ipv4				\
		md-rule md.dst_address_offset				\
		md-rule md.src_address_offset 				\
		md-rule md.ipproto_offset

# This is a metalist for TCP metadata similar to above IPv4.
ipcmd parser create metalist name mdl.tcp				\
		md-rule md.tcp.src_port					\
		md-rule md.tcp.dst_port

# Creates a parse node object identified by name "node.ether"
# This node represents the rules for parsing the ethernet header.
# `hdr.minlen 14` specifies minimum length of the ethernet header as 14 bytes.
# `nxt.offset 12` specifies the offset of the next protocol field for ethernet
# (in this case, it is start of the ethtype field in the ethernet header).
# `nxt.length 2` specifies the length of the ethtype field in the ethernet
# header. The extracted next protocol value from nxt.offset and nxt.length is
# used for next protocol lookup from the nxt.table (table.ether was defined
# earlier).
ipcmd parser create node name node.ether				\
		hdr.minlen 14						\
		nxt.offset 12						\
		nxt.length 2						\
		nxt.table table.ether

# Creates a parse node object identified by name "node.ipv4"
# This node represents the rules for parsing the IPv4 header.
# `hdr.minlen 20` specifies minimum length of the IPv4 header must be 20 bytes.
# `hdr.lenoff 0` specifies the byte offset position of the actual IPv4 header
# length field from the beginning of the IPv4 header.
# `hdr.lenlen 1` specifies length of the packet headerlength field in bytes(i.e.
# length of the IPv4 header length field).
# hdr.lenoff and hdr.lenlen attributes are used to locate the header length
# field in the IPv4 header.
# `hdrlenmask 0x0f` specifies mask value used to perform "bitwise AND" with the
# IPv4's header length field's value.
# `hdr.lenmultiplier 4` specifies the value to multiply (i.e. right shift bits)
# with the IPv4 header length field's masked value.
# Since IPv4's header length is dynamic, the actual header length needs to be
# calculated using these attributes hdr.lenmask and hdr.lenmultiplier.
# nxt.offset and nxt.length are similar to above ethernet header, these are used
# to extract the ipproto field in IPv4 header. 
# `nxt.table table.ip` is the lookup table for ipproto number.
# `metalist mdl.ipv4` specifies to execute all the metadata extraction rules
# associated with mdl.ipv4 and store the derived/parsed IPv4 packet data in
# user specified metadata buffer.
# length_field_value = TODO:
# hdr_len = (hdr.lenmultiplier * length_field_value) + hdr.add
ipcmd parser create node name node.ipv4					\
		hdr.minlen 20 						\
		hdr.lenoff 0						\
		hdr.lenlen 1						\
		hdr.lenmask 0x0f					\
		hdr.lenmultiplier 4					\
		nxt.offset 9						\
		nxt.length 1						\
		nxt.table table.ip					\
		metalist mdl.ipv4

# Creates a parse node object identified by name "node.tcp"
# This node represents the rules for parsing the TCP header.
# All the attributes here are similar to above defined node.ipv4, but defined
# for TCP protocol header parsing and executing TCP header related metadata
# extraction rules.
ipcmd parser create node name node.tcp					\
		hdr.minlen 20						\
		hdr.lenoff 12						\
		hdr.lenlen 1						\
		hdr.lenmask 0xf0					\
		hdr.lenmultiplier 4					\
		metalist mdl.tcp

# Creates an entry to the previously created empty lookup table named
# table.ether
# Table's entry points to the previously created parse node identified by
# name "node.ipv4". key 0x800 specifies the ethernet's protocol value for IPv4.
# This entry associates a protocol number with a parse node.
ipcmd parser create table/table.ether					\
		key 0x800						\
		node node.ipv4

# Creates an entry to the previously created empty lookup table named
# table.ip
# Table's entry points to the previously created parse node identified by
# name "node.tcp". key 0x6 specifies the IPv4's protocol value for TCP.
ipcmd parser create table/table.ip					\
		key 0x6							\
		node node.tcp

# Creates a parser object identified by name "test_parser"
# metametasize specifies the user specified metadata buffer size. This value
# must be less than or equal to the user passed buffer's size in the API
# kparser_parse(). Also user must not send smaller metadata buffer in API
# than what is being configured here using metametasize.
# In this example, the user metadata buffer can be interpreted as:
# struct usermetadata {
#        __u16 ipproto_offset;
#        __u16 src_ip_offset;
#        __u16 dst_ip_offset;
#        __u16 src_port_offset;
#        __u16 dst_port_offset;
# } __packed;
# Hence the `metametasize` should be sizeof(struct usermetadata), i.e. 10
# rootnode specifies the name of the protocol root node of this parser instance.
# node.ether is specified as rootnode since this parser starts parsing from
# ethernet packet.
ipcmd parser create parser name test_parser				\
		metametasize 10						\
		rootnode node.ether
