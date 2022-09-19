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
ipcmd parser create metadata-rule name md.ipv4.ttl		\
		type bit_offset					\
		md-off 0					\
		addoff 64

ipcmd parser create metadata-rule name md.ipv4.ipproto_offset	\
		type bit_offset					\
		md-off 2					\
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

# Creates a metalist object to be associated with a parse node. 
ipcmd parser create metalist name mdl.ipv4				\
		md.rule md.ipv4.dst_address_offset			\
		md.rule md.ipv4.src_address_offset			\
		md.rule md.ipv4.ttl              			\
		md.rule md.ipv4.ipproto_offset

ipcmd parser create metalist name mdl.tcp				\
		md.rule md.tcp.src_port					\
		md.rule md.tcp.dst_port

# Creates a parse nodes. Contains header size and how to calculate next header
ipcmd parser create node name node.ether				\
		min-hdr-length 14					\
		nxt.field-off 12					\
		nxt.field-len 2						\
		nxt.table table.ether

ipcmd parser create node name node.ipv4					\
		min-hdr-length 20 					\
		nxt.field-off 9						\
		nxt.field-len 1						\
		nxt.table table.ip					\
		metalist mdl.ipv4

ipcmd parser create node name node.tcp					\
		min-hdr-length 20					\
		metalist mdl.tcp

# Populate lookup tables.
ipcmd parser create table/table.ether					\
		key 0x800						\
		node node.ipv4

ipcmd parser create table/table.ip					\
		key 0x6							\
		node node.tcp

# Creates a parser object and specifies starting node
ipcmd parser create parser name test_parser				\
		metametasize 16						\
		rootnode node.ether
