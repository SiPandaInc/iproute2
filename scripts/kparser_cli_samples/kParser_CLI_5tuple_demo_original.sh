#!/bin/bash

<< ////
/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD */
/* Copyright (c) 2022, SiPanda Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Author:     Pratyush Kumar Khan <pratyush@sipanda.io>
 */
////

# This is a sample demo script which creates a kParser instance named
# "test_parser" for parsing bit offsets for five tuples of TCP-IP header,
# i.e. ipproto, ipv4 source address, ipv4 destination address, tcp source port,
# tcp destination port. UDP ports were added later.

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

# Creates a lookup table object named table.ip
# It is used to lookup ipproto (in this case only tcp).
# Entries of this table will be added later in this script.
# ipcmd parser create table name table.ip
ipcmd parser create table name table.ip

# Creates a lookup table object named table.ether
# It is used to lookup ethproto (in this case only IPv4).
# Entries of this table will be added later in this script.
ipcmd parser create table name table.ether

# This is a metadata extraction rule to derive the bit offset of ipproto field
# from packet and store in the user provided metadata buffer.
# `type bit_offset` specifies the operation type of this metadata is to derive
# the offset of the bit field from the packet.
# `md-off 0` means the derived data will be written at byte destination offset 0
# in the user provided metadata buffer.
# `addoff 72` specifies the bit offset of the ipproto field relative to the
# beginning of the IPv4 header.
# Note that for `type bit_offset`, the metadata is always 2 bytes written to
# user specified metadata buffer.
# Value written to metadata buffer will be absolute bit offset of IPv4 header +
# addoff.
ipcmd parser create metadata-rule name md.ipv4.ttl			\
		type bit_offset						\
		md-off 0						\
		addoff 64

ipcmd parser create metadata-rule name md.ipv4.ipproto_offset		\
		type bit_offset						\
		md-off 2						\
		addoff 72

ipcmd parser create metadata-rule name md.ipv4.src_address_offset	\
		type bit_offset						\
		addoff 96						\
		md-off 4

ipcmd parser create metadata-rule name md.ipv4.dst_address_offset	\
		type bit_offset						\
		addoff 128						\
		md-off 6

ipcmd parser create metadata-rule name md.tcp.src_port			\
		type bit_offset						\
		addoff 0						\
		md-off 8

ipcmd parser create metadata-rule name md.tcp.dst_port			\
		type bit_offset						\
		addoff 16						\
		md-off 10

ipcmd parser create metadata-rule name md.udp.src_port			\
		type bit_offset						\
		addoff 0						\
		md-off 12

ipcmd parser create metadata-rule name md.udp.dst_port			\
		type bit_offset						\
		addoff 16						\
		md-off 14

# Creates a metalist object identified by name "mdl.ipv4", which will later be
# associated with a parse node. 
# metalist is a collection of previously defined metadata extraction rules
# related to a specific protocol (IPv4 in this case).
ipcmd parser create metadata-ruleset name mdl.ipv4			\
		md.rule md.ipv4.ttl					\
		md.rule md.ipv4.ipproto_offset 				\
		md.rule md.ipv4.src_address_offset			\
		md.rule md.ipv4.dst_address_offset

# This is a metalist for TCP metadata similar to above IPv4.
ipcmd parser create metadata-ruleset name mdl.tcp			\
		md.rule md.tcp.src_port					\
		md.rule md.tcp.dst_port

# Explicitly define a metalist (i.e. metadata-ruleset) for UDP
ipcmd parser create metadata-ruleset name mdl.udp			\
		md.rule md.udp.src_port					\
		md.rule md.udp.dst_port

# Define udp parse node and explicitly attach it with metadata-ruleset for UDP
ipcmd parser create node name node.udp                                  \
                min-hdr-length 8                                        \
                md.ruleset mdl.udp

# Creates a parse node object identified by name "node.ether"
# This node represents the rules for parsing the ethernet header.
# `min-hdr-length 14` specifies minimum length of the ethernet header as 14
# bytes.
# `nxt.offset 12` specifies the offset of the next protocol field for ethernet
# (in this case, it is start of the ethtype field in the ethernet header).
# `nxt.length 2` specifies the length of the ethtype field in the ethernet
# header. The extracted next protocol value from nxt.offset and nxt.length is
# used for next protocol lookup from the nxt.table (table.ether was defined
# earlier).
ipcmd parser create node name node.ether				\
		min-hdr-length 14					\
		nxt.field-off 12					\
		nxt.field-len 2						\
		nxt.table table.ether

# Creates a parse node object identified by name "node.ipv4"
# This node represents the rules for parsing the IPv4 header.
# `min-hdr-length 20` specifies minimum length of the IPv4 header must be 20
# bytes.
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
# Define IPv4 common proto parse node configs in a reusable shell variable
# for later reuse
IPv4protonode=$(cat <<-END
                min-hdr-length 20
                hdr.len.field-off 0
                hdr.len.mask 0x0f
                hdr.len.multiplier 4
                nxt.field-off 9
                nxt.field-len 1
END
)
ipcmd parser create node name node.ipv4                                 \
                $IPv4protonode                                          \
		nxt.table table.ip					\
		md.ruleset mdl.ipv4

# Creates a parse node object identified by name "node.tcp"
# This node represents the rules for parsing the TCP header.
# All the attributes here are similar to above defined node.ipv4, but defined
# for TCP protocol header parsing and executing TCP header related metadata
# extraction rules.
ipcmd parser create node name node.tcp					\
		min-hdr-length 20					\
		hdr.len.field-off 12					\
		hdr.len.mask 0xf0					\
		hdr.len.multiplier 4					\
		md.ruleset mdl.tcp					\

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

ipcmd parser create table/table.ip					\
		key 0x11						\
		node node.udp

# Creates a parser object identified by name "test_parser"
# metametasize specifies the user specified metadata buffer size. This value
# must be less than or equal to the user passed buffer's size in the API
# kparser_parse(). Also user must not send smaller metadata buffer in API
# than what is being configured here using metametasize.
# Hence the `metametasize` should be sizeof(struct usermetadata), i.e. 10
# rootnode specifies the name of the protocol root node of this parser instance.
# node.ether is specified as rootnode since this parser starts parsing from
# ethernet packet.
ipcmd parser create parser name test_parser				\
		metametasize 16						\
		rootnode node.ether

ipcmd parser read parser name test_parser

echo "This script passed!"
