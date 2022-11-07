# Convert a parser in .json representation to ipcmd parser commands
#
# Copyright SiPanda Inc., 2022
#

import json
import sys
from io import StringIO
from random import randint

print('''#!/bin/bash

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
 * Author:     Sumon Singh <sumon@sipanda.io>
 */
////

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
''')

# Utility function to write and error message and exit
def err(error):
	print("Error: %s" % error, file = sys.stderr)
	sys.exit()

# Utility function to check is a field exists in a JSON object. If the field
# does not exist, then exit with an error
def check_exist(key, struct, error):
	if key not in struct:
		err(error)

def check_list_not_exist(name, list, error):
	if name in list:
		err(error)

outputbuf = StringIO()

# Utility functions to output text
def output(text):
	outputbuf.write(text)

def outputnl(text):
	outputbuf.write(text)
	outputbuf.write("\n")

# List of of parsers
parser_list = {}
parser_id = 0x1000

def add_parser_to_list(parser, name):
	global parser_list
	global parser_id

	check_list_not_exist(name, parser_list,
		"%s already in parser list" % name)

	parser_list[name] = { "parser": parser, "id": parser_id }
	parser_id += 1

# List of of parse nodes
parse_node_list = {}
parse_node_id = 0

def add_parse_node_to_list(parse_node, name):
	global parse_node_list
	global parse_node_id

	check_list_not_exist(name, parse_node_list,
		"%s already in parse node list" % name)

	parse_node_list[name] = { "node": parse_node,
				  "id": parse_node_id }
	parse_node_id += 1

# List of TLV nodes
tlv_node_list = {}
tlv_node_id = 0x200

def add_tlv_node_to_list(tlv_node, name):
	global tlv_node_list
	global tlv_node_id

	check_list_not_exist(name, tlv_node_list,
		"%s already in TLV node list" % name)

	tlv_node_list[name] = { "node": tlv_node, "id": tlv_node_id }
	tlv_node_id += 1

# List of tables (protocol table and TLV tables, but not flag fields tables
table_list = {}
table_id = 0x400

def add_table_to_list(table, name):
	global table_list
	global table_id

	check_list_not_exist(name, table_list,
		"%s already in table list" % name)

	table_list[name] = { "table": table, "id": table_id }
	table_id += 1

# List of flag fields tables
flag_fields_list = {}
flag_fields_id = 0x800

def add_flag_fields_to_list(table, name):
	global flag_fields_list
	global flag_fields_id

	check_list_not_exist(name, flag_fields_list,
		"%s already in flag fields list" % name)

	flag_fields_list[name] = { "table": table, "id": flag_fields_id }
	flag_fields_id += 1

# List of metadata objects
metadata_objects_list = {}
metadata_objects_id = 0x4000

def add_metadata_object_to_list(metadata, name):
	global metadata_objects_list
	global metadata_objects_id

	check_list_not_exist(name, metadata_objects_list,
		"%s already in metadata objects list" % name)

	metadata_objects_list[name] = { "object": metadata, "id": metadata_objects_id }
	metadata_objects_id += 1

def get_metadata_object(name):
	global metadata_objects_list
	global metadata_objects_id

	check_exist(name, metadata_objects_list,
		"%s not found in metadata objects list" % name)

	return metadata_objects_list[name]

# List of metadata entries
metadata_list = {}
metadata_id = 0x3000

def add_metadata_to_list(metadata, name):
	global metadata_list
	global metadata_id

	check_list_not_exist(name, metadata_list,
		"%s already in metadata list" % name)

	metadata_list[name] = { "metadata": metadata, "id": metadata_id }
	metadata_id += 0x100

	if 'ents' in metadata:
		for instance in ents:
			name = "%s/%s" % (name, instance['name'])

def add_counter_actions_to_metadata(counter_actions, metadata_name):
	global metadata_list

	metadata = metadata_list[metadata_name]

	for ca in counter_actions:
		check_exist('name', ca,
				"'name' must be defined for counter action")
		check_exist('type', ca,
				"'type' must be defined for counter action")

		a = {
			'type': 'counter-mode',
			'counteridx': ca['name']
		}

		if ca['type'] in ['pre_metadata_inc', 'post_metadata_inc']:
			a['counterop'] = 'incr'
		elif ca['type'] in ['pre_metadata_reset', 'post_metadata_reset']:
			a['counterop'] = 'reset'
		else:
			err("Unknown counter action type '%s'" % ca['type'])

		print(metadata)

		if ca['type'] in ['pre_metadata_inc', 'pre_metadata_reset']:
			metadata['metadata'].insert(0, a)
		elif ca['type'] in ['post_metadata_inc', 'post_metadata_reset']:
			metadata['metadata'].append(a)
		else:
			err("Unknown counter action type '%s'" % ca['type'])

# List of conditional expressions
cond_exprs_list = {}
cond_exprs_id = 0x2000

def add_cond_exprs_to_list(cond_exprs, name):
	global cond_exprs_list
	global cond_exprs_id

	check_list_not_exist(name, cond_exprs_list,
		"%s already in conditional expression list" % name)

	cond_exprs_list[name] = { "table": cond_exprs, "id": cond_exprs_id }
	cond_exprs_id += 1

# List of flag fields nodes
flag_fields_node_list = {}
flag_fields_node_id = 0x2000

def add_flag_fields_node_to_list(flag_fields_node, name):
	global flag_fields_node_list
	global flag_fields_node_id

	check_list_not_exist(name, flag_fields_node_list,
		"%s already in flag fields node list" % name)

	flag_fields_node_list[name] = { "node": flag_fields_node,
					"id": flag_fields_node_id }
	flag_fields_node_id += 1

# Output ipcmd commands to create metadata instances. Read the global metadata
# list and output a create metadata command for each entry
def output_ipcmd_metadata():
	global metadata_list

	if metadata_list == {}:
		return

	outputnl("# Create metadata instances and list")

	for metadata_name in metadata_list:
		metadata = metadata_list[metadata_name]['metadata']
		mid = metadata_list[metadata_name]['id']
		id = mid + 1
		mylist = []
		for instance in metadata:
			# Create each instance of metadata
			if 'name' in instance:
				name = "%s.%s" % (metadata_name,
						  instance['name'])
				output("ipcmd parser create metadata-rule name %s" % name)
				mylist.append(name)
			else:
				name = "%s.%i" % (metadata_name, id)
				mylist.append(name)
				output("ipcmd parser create metadata-rule name %s" % name)

			id += 1
			if 'type' not in instance:
				if 'hdr-src-off' in instance:
					# If src_off is a field and type is not
					# present assume metadata type is
					# hdrdata
					type = 'extract'
				elif 'constant' in instance:
					# If constant is present then assume
					# metadata type is constant
					type = 'constant'
				else:
					err("No metadata type for metadata")
			else:
				type = instance['type']

			if type == 'extract':
				check_exist('hdr-src-off', instance,
					    "'hdr-src-off' must defined for "
					    "hdrdata metadata %s" %
					    metadata_name)

				output(" type hdrdata hdr-src-off %s" % instance['hdr-src-off'])
			elif type == 'offset':
				check_exist('hdr-src-off', instance,
					    "'hdr-src-off' must defined for "
					    "hdrdata metadata %s" %
					    metadata_name)

				output(" type offset addoff %s" % instance['hdr-src-off'])

				#if 'length' not in instance:
				#	instance['length'] = 2 # default length for offset metadata
			elif type == 'bit_offset':
				check_exist('hdr-src-off', instance,
					    "'hdr-src-off' must defined for "
					    "hdrdata metadata %s" %
					    metadata_name)

				output(" type bit_offset addoff %s" % instance['hdr-src-off'])

				#if 'length' not in instance:
				#	instance['length'] = 2 # default length for offset metadata
			elif type == 'nibb_extract':
				check_exist('hdr-src-off', instance,
					    "'hdr-src-off' must defined for "
					    "nibb_extract metadata %s" %
					    metadata_name)

				output(" type nibbs_hdrdata hdr-src-off %s" % instance['hdr-src-off'])
			elif type == 'constant':
				check_exist('value', instance,
					    "'value' must defined for "
					    "hdrdata metadata %s" %
					    metadata_name)

				if 'length' not in instance:
					instance['length'] = 2 # default length for constant metadata

				if instance['length'] == 1:
					tp = 'constant_byte'
				elif instance['length'] == 2:
					tp = 'constant_halfword'
				else:
					err("Constante of size %s is not supported by ipcmd" %
							instance['length'])

				output(" type %s constantvalue %s" % (type, instance['value']))

			elif type == 'hdr_length':
				output(" type hdrlen")
			elif type == 'num_encaps':
				output(" type numencaps")
			elif type == 'num_nodes':
				output(" type numnodes")
			elif type == 'timestamp':
				output(" type timestamp")
			elif type == 'return_code':
				output(" type return-code")
			elif type == 'counter-mode':
				check_exist('counterop', instance,
						"'counter-mode' metadata must contain 'counterop'")
				check_exist('counteridx', instance,
						"'counter-mode' metadata must contain 'counteridx'")

				outputnl(" type counter-mode counteridx %s counterop %s " %
						(instance['counteridx'], instance['counterop']))
				continue
			else:
				# Need to add other types of metadata
				err("Unknown metadata type %s" % type)

			# Destination offset in metadata structure
			check_exist('md-off', instance,
				    "'md-off' must defined for metadata %s" %
				     metadata_name)

			length = 'length' if type != 'nibb_extract' else 'nibb-length'

			# Length of data to write
			#check_exist(length, instance,
			#	    "'%s' must defined for metadata %s" %
			#	     (length, metadata_name))

			if 'is-frame' in instance:
				val = 'true' if instance['is-frame'] else 'false'
				output(" isframe %s" % val)

			if 'endian-swap' in instance:
				val = 'true' if instance['endian-swap'] else 'false'
				output(" host-order-conversion %s" % val)

			if 'index' in instance:
				output(" counteridx %s" % instance['index'])

			outputnl(" md-off %s " % (instance['md-off']))

		if mylist != []:
			# Create a metalist for this set of metadata
			output("ipcmd parser create metadata-ruleset name %s" % metadata_name)
			for name in mylist:
				output(" md.rule %s" % name)
			outputnl("")
			outputnl("")

# Output ipcmd commands to create create proto tables. Read the global list of
# tables and and output a create table command for each entry
def output_ipcmd_tables():
	global table_list

	if table_list == {}:
		return

	outputnl("# Create protocol tables")

	for table_name in table_list:
		id = table_list[table_name]['id']
		table = table_list[table_name]['table']
		output("ipcmd parser create table name %s" % table_name)
		if 'default' in table:
		  output(" default %s" % table['default'])
		outputnl("")
	outputnl("")

# Output ipcmd commands to create flagfields tables. Read the global list of
# flag fields and and output a create flagfields command for each entry
def output_ipcmd_flag_fields_tables():
	global flag_fields_list

	if flag_fields_list == {}:
		return

	outputnl("# Create flag fields tables")

	for table_name in flag_fields_list:
		id = flag_fields_list[table_name]['id']
		outputnl("ipcmd parser create flagfields name %s.fields" % table_name)
		outputnl("ipcmd parser create flagstable name %s" % table_name)
	outputnl("")

# Output ipcmd commands to create table entries. Read the global list of
# tables and for each table do a create table/... command to add an entry to
# the table
def output_ipcmd_table_ents():
	global table_list

	if table_list == {}:
		return

	outputnl("# Create proto table entries")

	for table_name in table_list:
		table = table_list[table_name]['table']['ents']
		#cnt = 0
		for entry in table:
			check_exist('key', entry, "'key' must be defined for "
				    "entry in table %s" % table_name)
			check_exist('node', entry, "'node' must be defined for "
				    "entry in table %s" % table_name)
			output("ipcmd parser create table/%s" %
			       (table_name))
			if 'name' in entry:
				output(" name %s.tabent.%s" %
				       (table_name, entry['name']))
			output(" key %s node %s" %
			         (entry['key'], entry['node']))

			if 'encap' in entry:
				val = 'true' if entry['encap'] else 'false'
				output(" encap %s" % val)

			outputnl("")
			#cnt += 1
	outputnl("")

# Output ipcmd commands to create flag_fields entries. Read the global list of
# flag_fields and for each table do a create flagfield/... command to add an
# entry to the table
def output_ipcmd_flag_fields():
	global flag_fields_list

	if flag_fields_list == {}:
		return

	outputnl("# Create flag field entries")

	for table_name in flag_fields_list:
		table = flag_fields_list[table_name]['table']
		cnt = 0
		for entry in table:
			check_exist('flag', entry, "'flag' must be defined for "
				    "entry in flag fields table %s" %
				    table_name)
			check_exist('field-len', entry, "'field-len' "
				    "must be defined for entry in flag fields "
				    "table %s" % table_name)

			outputnl("ipcmd parser create flag name %s-%d flag %s size %d" %
					(table_name, cnt, entry['flag'], entry['field-len']))

			outputnl("ipcmd parser create flagfields/%s.fields/%d flag %s-%d key %d" %
			      (table_name, cnt, table_name, cnt, cnt))


			if 'node' in entry:
				output("ipcmd parser create flagstable/%s/%d flagid %d" %
			       (table_name, cnt, cnt))
				outputnl(" flagsnode %s" % entry['node'])

			outputnl("")
			cnt += 1
	outputnl("")

# Output a metadata list ID for a parse node or TLV node ipcmd command
def output_ipcmd_node_metadata(metadata, node_name):
	if 'ents' in metadata:
		table_name = "%s.metadata" % node_name
	elif 'list' in metadata:
		table_name = metadata['list']
	if table_name not in metadata_list:
		err("Cannot find %s in metadata list" %
				    table_name)
	output(" md.ruleset %s" % table_name)

def output_ipcmd_node_cond_exprs(cond_expr, node_name):
	if 'ents' in cond_expr:
		table_name = "%s.cond_exprs" % node_name
	elif 'list' in cond_expr:
		table_name = cond_expr['list']

	if table_name not in cond_exprs_list:
		err("Cannot find %s in metadata list" %
				table_name)

	output(" condexprstable % s" % table_name)

# Output TLV parameters for a ipcmd command to create parse nodes
def output_ipcmd_node_tlv_node(tlv_parse_node, node_name):
	defaults = {
			'continue': 'err', # missing?
			'wild': 'err', # missing?
			'alt_wild': 'err', # missing?
			'stop_okay': 'stop-okay',
			'stop_fail': 'stop-fail',
			'stop_node_okay': 'err', # stop-subnode-fail?
			'stop_sub_node_okay': 'stop-subnode-okay'
	}

	if 'ents' in tlv_parse_node:
		table_name = "%s.tlv_table" % node_name
	elif 'table' in tlv_parse_node:
		table_name = tlv_parse_node['table']
	else:
		err("No ents or table in TLV parse node for %s" % node_name)
		sys.exit()

	check_exist(table_name, table_list,
		    "Cannot find table %s for TLV parse node " \
		    "%s" % (table_name, node_name))

	table_id = table_list[table_name]['id']

	output(" tlvs.table 0x%x" % table_id)

	if 'start-offset' in tlv_parse_node:
		if isinstance(tlv_parse_node['start-offset'], dict):
			start_off = tlv_parse_node['start-offset']
			check_exist('field-off', start_off, "'field-off' must be defined "
					"must must be defined for dynamic start offset in %s"
					% node_name)
			check_exist('field-len', start_off, "'field-len' must be defined "
					"must must be defined for dynamic start offset in %s"
					% node_name)

			output(" tlvs.startoff.variableoff.field-off %s"
					% start_off['field-off'])
			output(" tlvs.startoff.variableoff.field-len %s"
					% start_off['field-len'])

			if 'mask' in start_off:
				output(" tlvs.startoff.variableoff.mask %s"
						% start_off['mask'])
			if 'endian-swap' in start_off:
				output(" tlvs.startoff.variableoff.host-order-conversion %s"
						% str(start_off['endian-swap']).lower())
			if 'add' in start_off:
				output(" tlvs.startoff.variableoff.addvalue %s"
						% start_off['add'])
			if 'multiplier' in start_off:
				output(" tlvs.startoff.variableoff.multiplier %s"
						% start_off['multiplier'])
		else:
			output(" tlvs.startoff.constantoff %u" %
					tlv_parse_node['start-offset'])

	check_exist('tlv-type', tlv_parse_node, "'tlv-type' "
		    "must be defined for tlv-parse-node in %s" % node_name)
	tlv_type = tlv_parse_node['tlv-type']
	check_exist('field-off', tlv_type, "'field-off' must be defined for "
		    "tlv-type in tlv-parse-node in %s" % node_name)
	check_exist('field-len', tlv_type, "'field-len' must be defined for "
		    "tlv-type in tlv-parse-node in %s" % node_name)
	output(" tlvs.type.field-off %u tlvs.type.field-len %u" %
	       (tlv_type['field-off'], tlv_type['field-len']))
	if 'mask' in tlv_type:
		output(" tlvs.type.mask %s" % tlv_type['mask'])

	check_exist('tlv-length', tlv_parse_node, "'tlv-length' "
		    "must be defined for tlv-parse-node in %s" % node_name)
	tlv_length = tlv_parse_node['tlv-length']
	check_exist('field-off', tlv_length, "'field-off' must be defined for "
		    "tlv-length in tlv-parse-node in %s" % node_name)
	check_exist('field-len', tlv_length, "'field-len' must be defined for "
		    "tlv-length in tlv-parse-node in %s" % node_name)
	output(" tlvs.len.field-off %u tlvs.len.field-len %u" %
	       (tlv_length['field-off'], tlv_length['field-len']))
	if 'mask' in tlv_length:
		output(" tlvs.len.mask %s" % tlv_length['mask'])
	if 'add' in tlv_length:
		output(" tlvs.len.addvalue %s" % tlv_length['add'])
	if 'multiplier' in tlv_length:
		output(" tlvs.len.multiplier %s" % tlv_length['multiplier'])
	if 'endian-swap' in tlv_length:
		output(" tlvs.len.host-order-conversion %s" % str(tlv_length['endian-swap']).lower())

	if 'pad1' in tlv_parse_node:
		output(" tlvs.pad1 %u" % tlv_parse_node['pad1'])
	if 'padn' in tlv_parse_node:
		output(" tlvs.padn %u" % tlv_parse_node['padn'])
	if 'eol' in tlv_parse_node:
		output(" tlvs.eol %u" % tlv_parse_node['eol'])

	if 'min-hdr-length' in tlv_parse_node:
		output(" tlvs.min-hdr-length %s" % tlv_parse_node['min-hdr-length'])
	if 'default' in tlv_parse_node:
		output(" tlvs.defaultfail %s" % defaults[tlv_parse_node['default']])
	if 'wildcard-node' in tlv_parse_node:
		output(" tlvs.wildcardnode %s" % tlv_parse_node['wildcard-node'])

	if 'max-tlvs' in tlv_parse_node:
		output(" tlvs.maxloop %s" % tlv_parse_node['max-tlvs'])
	if 'max-non-padding' in tlv_parse_node:
		output(" tlvs.maxnon %s" % tlv_parse_node['max-tlvs'])
	if 'max-padding-length' in tlv_parse_node:
		output(" tlvs.maxplen %s" % tlv_parse_node['max-padding-length'])
	if 'max-consecutive-padding' in tlv_parse_node:
		output(" tlvs.maxcpad %s" % tlv_parse_node['max-consecutive-padding'])
	if 'disp-limit-exceeded' in tlv_parse_node:
		output(" tlvs.displimitexceed %s" % tlv_parse_node['disp-limit-exceeded'])
	if 'loop-count-exceeded-is-err' in tlv_parse_node:
		output(" tlvs.exceedloopcntiserr %s" % tlv_parse_node['loop-count-exceeded-is-err'])

# Output flag fields  parameters for a ipcmd command to create parse nodes
def output_ipcmd_node_flag_fields_node(flag_fields_parse_node, node_name, node):
	if 'ents' in flag_fields_parse_node:
		table_name = "%s.flag_fields" % node_name
	elif 'table' in flag_fields_parse_node:
		table_name = flag_fields_parse_node['table']
	else:
		err("No ents or table in flag fields parse "
		    "node for %s" % node_name)

	check_exist(table_name, flag_fields_list,
		    "Cannot find table %s for flag fields parse node %s" %
		    (table_name, node_name))

	output(" flags.fields-table %s.fields flags.fields-proto-table %s" % (table_name, table_name))

	check_exist('flags-offset', flag_fields_parse_node,
		    "'flags-offset' must be defined for "
		    "flag-fields-parse-node %s" % node_name)
	check_exist('flags-length', flag_fields_parse_node,
		    "'flags-length' must be defined for "
		    "flag-fields-parse-node %s" % node_name)

	output(" flags.field-off %u flags.field-len %u" %
	       (flag_fields_parse_node['flags-offset'],
		flag_fields_parse_node['flags-length']))

	if 'flags-mask' in flag_fields_parse_node:
		output(" flags.field-mask %s" % flag_fields_parse_node['flags-mask'])
	if 'endian-swap' in flag_fields_parse_node:
		output(" flags.field-host-order-conversion %s" %
				str(flag_fields_parse_node['endian-swap']).lower())

	if 'hdr-length' in flag_fields_parse_node:
		if 'hdr-length' in node:
			err("'hdr_len' cannot be in both a parse node and its "
			    "flag-fields-parse-node")
		hdr_length = flag_fields_parse_node['hdr-length']
		if 'flag-fields-length' in hdr_length and \
		    hdr_length['flag-fields-length']:
			output(" flags.field-hdrlen")

def output_parse_node(node_name, node, id):
	defaults = {
			'continue': 'err', # missing?
			'wild': 'err', # missing?
			'alt_wild': 'err', # missing?
			'stop_okay': 'stop-okay',
			'stop_fail': 'stop-fail',
			'stop_node_okay': 'err', # stop-subnode-fail?
			'stop_sub_node_okay': 'stop-subnode-okay'
	}

	output("ipcmd parser create node name %s" % node_name)
	if node_name != 'okay_node' and node_name != 'fail_node':
		check_exist('min-hdr-length', node, "'min-hdr-length' must be defined for "
		        "parse_node %s" % node_name)
		output(" min-hdr-length %s" % node['min-hdr-length'])

	if 'hdr-length' in node and 'flag-fields-parse-node' not in node: # Variable length header
		hdr_length = node['hdr-length']
		check_exist('field-off', hdr_length, "'field-off' must be defined "
			    "for hdr-length in parse-node in %s" % node_name)
		check_exist('field-len', hdr_length, "'field-len' must be defined "
			    "for hdr-length in parse-node in %s" % node_name)
		output(" hdr.len.field-off %u hdr.len.field-len %u" %
		       (hdr_length['field-off'], hdr_length['field-len']))
		if 'endian-swap' in hdr_length:
			output(" hdr.len.host-order-conversion %s" %
				str(hdr_length['endian-swap']).lower())
		if 'mask' in hdr_length:
			output(" hdr.len.mask %s" % hdr_length['mask'])
		if 'multiplier' in hdr_length:
			output(" hdr.len.multiplier %u" % hdr_length['multiplier'])
		if 'add' in hdr_length:
			output(" hdr.len.addvalue %u" % hdr_length['add'])

	if 'next-proto' in node: # Non-leaf node
		next_proto = node['next-proto']
		check_exist('field-off', next_proto, "'field-off' must be defined "
			    "for next-proto in parse-node in %s" % node_name)
		check_exist('field-len', next_proto, "'field-len' must be defined "
			    "for next-proto in parse-node in %s" % node_name)
		if 'ents' in next_proto:
			table_name = "%s.next_proto" % node_name
		elif 'table' in next_proto:
			#output(" nxt.table %s" %next_proto['table'])
			table_name = next_proto['table']
		else:
			err("No ents or table in next proto")

		check_exist(table_name, table_list,
			    "Cannot find table %s for parse node "
			    "%s" % (table_name, node_name))
		table_id = table_list[table_name]['id']

		output(" nxt.field-off %u nxt.field-len %u" %
		       (next_proto['field-off'], next_proto['field-len']))
		#output(" prottable 0x%x" % table_id)
		output(" nxt.table %s" %table_name)

		if 'wildcard-node' in next_proto:
			output(" nxt.wildcard-node %s" % next_proto['wildcard_node'])

		if 'mask' in next_proto:
			output(" nxt.mask %s" % next_proto['mask'])

		if 'default' in next_proto:
			output(" defaultfail %s" % defaults[next_proto['default']])

	# next node?

	if 'tlv-parse-node' in node: # TLVs parse node
		if 'flag-fields-parse-node' in node:
			err("Parse node %s cannot be both a TLV parse "
			    "node and a flag fields parse node")
		tlv_parse_node = node['tlv-parse-node']
		output_ipcmd_node_tlv_node(tlv_parse_node, node_name)

	elif 'flag-fields-parse-node' in node:
		flag_fields_parse_node = node['flag-fields-parse-node']
		output_ipcmd_node_flag_fields_node(flag_fields_parse_node,
						node_name, node)

	if 'cond-exprs' in node:
		output_ipcmd_node_cond_exprs(node['cond-exprs'], node_name)

	if 'metadata' in node:
		output_ipcmd_node_metadata(node['metadata'], node_name)

	outputnl("")

# Output ipcmd commands to create parse nodes. Read the global list of parse nodes
# and for each each one do a create node command. This also handles TLV parse
# nodes and flag fields parse nodes
def output_ipcmd_parse_nodes():
	global parse_node_list
	global table_list

	if parse_node_list == {}:
		return

	outputnl("# Create parse nodes")

	for node_name in parse_node_list:
		id = parse_node_list[node_name]['id']
		node = parse_node_list[node_name]['node']
		output_parse_node(node_name, node, id)

	outputnl("")

# Output ipcmd commands to create TLV nodes. Read the global list of TLV nodes
# and for each do a create TLV node command
def output_ipcmd_tlv_nodes():
	global tlv_node_list
	global table_list

	defaults = {
			'continue': 'err', # missing?
			'wild': 'err', # missing?
			'alt_wild': 'err', # missing?
			'stop_okay': 'stop-okay',
			'stop_fail': 'stop-fail',
			'stop_node_okay': 'err', # stop-subnode-fail?
			'stop_sub_node_okay': 'stop-subnode-okay'
	}

	if tlv_node_list == {}:
		return

	outputnl("# Create TLV nodes")

	for tlv_node_name in tlv_node_list:
		id = tlv_node_list[tlv_node_name]['id']
		tlv_node = tlv_node_list[tlv_node_name]['node']
		output("ipcmd parser create tlvnode name %s" % tlv_node_name)

		if 'min-hdr-length' in tlv_node:
			output(" min-hdr-length %s" % node['min-hdr-length'])

		if 'overlay-node' in tlv_node:
			overlay_tlv = tlv_node['overlay-node']
			check_exist('field-off', overlay_tlv, "'field-off' must be defined "
					"for overlay tlv %s" % tlv_node_name)
			check_exist('field-len', overlay_tlv, "'field-len' must be defined "
					"for overlay tlv %s" % tlv_node_name)
			if 'ents' in overlay_tlv:
				table_name = "%s.tlv_overlay" % tlv_node_name
			elif 'table' in next_proto:
				table_name = overlay_tlv['table']
			else:
				err("No ents or table in TLV node")

			check_exist(table_name, table_list,
				    "Cannot find table %s for TLV overlay node "
				    "%s" % (table_name, tlv_node_name))
			table_id = table_list[table_name]['id']

			output(" overlay.type.field-off %u overlay.type.field-len %u" %
				(overlay_tlv['field-off'], overlay_tlv['field-len']))
			output(" overlay-tlvs-table %s" %table_name)

			if 'wildcard-node' in overlay_tlv:
				output(" overlay-wildcard-parse-node %s" % overlay_tlv['wildcard_node'])

			if 'mask' in overlay_tlv:
				output(" overlay.type.mask %s" % overlay_tlv['mask'])

			if 'default' in overlay_tlv:
				output(" defaultfail %s" % defaults[next_proto['default']])

		if 'metadata' in tlv_node:
			output_ipcmd_node_metadata(tlv_node['metadata'],
					     tlv_node_name)

		if 'cond-exprs' in tlv_node:
			output_ipcmd_node_cond_exprs(tlv_node['cond-exprs'], tlv_node_name)

		outputnl("")
	outputnl("")

# Output ipcmd commands to create flag fields nodes. Read the global list of flag fields nodes
# and for each do a create flag fields node command
def output_ipcmd_flag_fields_nodes():
	global flag_fields_node_list
	global table_list

	if flag_fields_node_list == {}:
		return

	outputnl("# Create flag fields nodes nodes")

	for flag_fields_node_name in flag_fields_node_list:
		flag_fields_node = flag_fields_node_list[flag_fields_node_name]['node']
		output("ipcmd parser create flagsnode name %s" % flag_fields_node_name)

		if 'metadata' in flag_fields_node:
			output_ipcmd_node_metadata(flag_fields_node['metadata'],
					     flag_fields_node_name)

		if 'cond-exprs' in flag_fields_node:
			output_ipcmd_node_cond_exprs(flag_fields_node['cond-exprs'],
						flag_fields_node_name)

		outputnl("")
	outputnl("")

# Output ipcmd commands to create conditional expression. Read the global
# conditional expressions list and output a create command for each entry
def output_ipcmd_cond_exprs():
	global cond_exprs_list

	if cond_exprs_list == {}:
		return

	defaults = {
			'stop_okay': 'stop-okay',
			'stop_fail': 'stop-fail',
			'stop_node': 'err', # stop-subnode-fail?
			'stop_sub': 'stop-subnode-okay'
	}

	counter = 0
	outputnl("# Create conditional expression and lists")

	def output_expr(expr, default):
		nonlocal counter
		nonlocal defaults

		if 'name' in expr:
			name = expr['name']
		else:
			name = "__autogen_cnd_expr.%d" % counter
			counter += 1

		check_exist('type', expr, "'type' must be defined "
				"for conditional expression %s" % name)

		if expr['type'] in [ 'and', 'or' ]:
			check_exist('ents', expr, "'ents' must be "
				    "defined for conditional expression")

			sub_exprs = [output_expr(se, default) for se in expr['ents']]
			output("ipcmd parser create condexprslist name %s" % name)

			outputnl(" defaultfail %s" % defaults[default])

			cntr = 0
			for se in sub_exprs:
				outputnl("ipcmd parser create condexprslist/%d condexprs %s" %
							(cntr, se))
				cntr += 1
		else:
			check_exist('field-off', expr, "'field-off' must be "
				    "defined for conditional expression %s" % name)
			check_exist('field-len', expr, "'field-len' must be "
				    "defined for conditional expression %s" % name)
			check_exist('value', expr, "'value' must be "
				    "defined for conditional expression %s" % name)

			output("ipcmd parser create condexprs name %s" % name)

			types = {
				'equal': 'equal',
				'not_equal': 'notequal',
				'greater_than': 'greaterthan',
				'greater_or_equal': 'greaterthanequal',
				'less_than': 'lessthan',
				'less_or_equal': 'lessthanequal'
			}

			output(" type %s src.field-off %d src.field-len %d value %d" %
						(types[expr['type']], expr['field-off'],
						 expr['field-len'], expr['value']))

			if 'mask' in expr:
				output(" mask %s" % expr['mask'])

			outputnl("")

		return name

	for cond_exprs_name in cond_exprs_list:
		cond_exprs = cond_exprs_list[cond_exprs_name]['table']
		mid = cond_exprs_list[cond_exprs_name]['id']
		id = mid + 1
		mylist = []

		if 'default-fail' in cond_exprs:
			default = cond_exprs['default-fail']
		else:
			default = 'stop_okay'

		for instance in cond_exprs['ents']:
			expr_name = output_expr(instance, default)

			# must wrap single expr in a condexprslist
			if instance['type'] not in ['and', 'or']:
				name = "__autogen_cnd_expr.%d" % counter
				counter += 1

				output("ipcmd parser create condexprslist name %s" % name)
				outputnl(" defaultfail %s" % defaults[default])
				outputnl("ipcmd parser create condexprslist/0 condexprs %s"
							% expr_name)

				expr_name = name

			mylist.append(expr_name)

		if mylist != []:
			# Create a metalist for this set of metadata
			outputnl("ipcmd parser create condexprstable name %s "
					% cond_exprs_name)

			for (i, name) in enumerate(mylist):
				outputnl("ipcmd parser create condexprstable/%d "
						 "condexprslist %s " % (i, name))

			outputnl("")

# Out ipcmd commands to create parsers. For each entry in the parser list
# do a create parser command
def output_ipcmd_parsers():
	global parser_list
	global table_list

	if parser_list == []:
		return

	outputnl("# Create parsers")

	for parser_name in parser_list:
		parser = parser_list[parser_name]['parser']
		check_exist('root-node', parser, "'root-node' must be "
			    "defined for parser %s" % parser_name)
		if parser['root-node'] not in parse_node_list:
			err("Parser %s has non existent root node %s" %
			    (parser_name, parser['root-node']))
		output("ipcmd parser create parser name %s" % parser_name)
		output(" rootnode %s" % parser['root-node'])

		if 'okay-target' in parser:
			if parser['okay-target'] not in parse_node_list:
				err("Parser %s has an undefined okay node %s" %
					(parser_name, parser['okay-target']))
			output(" oknode %s" % parser['okay-target'])

		if 'fail-target' in parser:
			if parser['fail-target'] not in parse_node_list:
				err("Parser %s has an undefined fail node %s" %
					(parser_name, parser['fail-target']))
			output(" failnode %s" % parser['fail-target'])

		if 'encap-target' in parser:
			if parser['encap-target'] not in parse_node_list:
				err("Parser %s has an undefined at encap node %s" %
					(parser_name, parser['encap-target']))
			output(" atencapnode %s" % parser['encap-target'])

		if 'max-nodes' in parser:
			output(" maxnodes %d" % parser['max-nodes'])

		if 'max-encaps' in parser:
			output(" maxencaps %d" % parser['max-encaps'])

		if 'max-frames' in parser:
			output(" maxframes %d" % parser['max-frames'])

		if 'metameta-size' in parser:
			output(" metametasize %d" % parser['metameta-size'])

		if 'frame-size' in parser:
			output(" framesize %d" % parser['frame-size'])

		outputnl("")
	outputnl("")

# Create a list of all the parsers from 'parsers' top level property
def preprocess_parsers(data):
	check_exist('parsers', data, "'parsers' must be defined")
	parsers = data['parsers']
	for parser in parsers:
		check_exist('name', parser, "'name' must be "
			    "defined for parser")
		add_parser_to_list(parser, parser['name'])

# Create a list of protocol tables for 'protocol_tables' top level property
def preprocess_proto_tables(data):
	if 'proto-tables' not in data:
		return
	proto_tables = data['proto-tables']

	for proto_table in proto_tables:
		check_exist('name', proto_table, "'name' must be "
			    "defined for proto-table")
		proto_table_name = proto_table['name']
		check_exist('ents', proto_table, "'ents' must be "
			    "defined for proto-table %s" % proto_table_name)
		add_table_to_list(proto_table, proto_table_name)

# Preprocess the parse nodes
def preprocess_parse_nodes(data):
	check_exist('parse-nodes', data,
		    "'parse-nodes' must be defined")
	parse_nodes = data['parse-nodes']
	for parse_node in parse_nodes:
		check_exist('name', parse_node, "'name' must be "
			    "defined for parse_node")

		# Add parse node to parse nodes list
		parse_node_name = parse_node['name']
		add_parse_node_to_list(parse_node, parse_node_name)

		if 'next-proto' in parse_node:
			next_proto = parse_node['next-proto']
			if 'ents' in next_proto:
				# Add embedded protocol table to the protocol
				# tables list
				table_name = "%s.next_proto" % parse_node_name
				add_table_to_list(next_proto, table_name)

		if 'metadata' in parse_node:
			metadata = parse_node['metadata']
			if 'ents' in metadata:
				# Add embedded metadata to the metadata liat
				table_name = "%s.metadata" % parse_node_name
				add_metadata_to_list(metadata['ents'],
						     table_name)

		if 'tlv-parse-node' in parse_node:
			tlv_parse_node = parse_node['tlv-parse-node']
			if 'ents' in tlv_parse_node:
				# Add embedded TLV table to protocol tables
				# list
				table_name = "%s.tlv_table" % parse_node_name
				add_table_to_list(tlv_parse_node, table_name)

		if 'flag-fields-parse-node' in parse_node:
			flag_fields_parse_node = parse_node[
						'flag-fields-parse-node']
			if 'ents' in flag_fields_parse_node:
				# Add embeeded flag fields to flag fields list
				table_name = "%s.flag_fields" % parse_node_name
				add_flag_fields_to_list(
					flag_fields_parse_node['ents'],
					table_name)

		if 'cond-exprs' in parse_node:
			cond_exprs = parse_node['cond-exprs']
			if 'ents' in cond_exprs:
				# Add embedded conditional expressions to
				# conditional expressions list
				table_name = "%s.cond_exprs" % parse_node_name
				add_cond_exprs_to_list(cond_exprs, table_name)

		if 'counter-actions' in parse_node:
			ca = parse_node['counter-actions']
			metadata = parse_node['metadata']
			metadata_name = ("%s.metadata" % parse_node_name) if 'ents' in metadata else metadata['list']
			add_counter_actions_to_metadata(ca, metadata_name)

		if 'next-node' in parse_node:
			table_name = "%s.next_node" % parse_node_name
			table = {
				'ents': [
					{
						'key': 0,
						'node': parse_node['next-node']
					}
				]
			}
			add_table_to_list(table, table_name)

			parse_node['next-proto'] = {
				'field-off': 0,
				'field-len': 1,
				'mask': '0x00',
				'table': table_name
			}

def preprocess_metadata_objects(data):
	if 'metadata-objects' not in data:
		return
	metadata_objects = data['metadata-objects']

	for metadata in metadata_objects:
		check_exist('name', metadata, "'name' must be "
			    "defined for metadata")
		# check_exist('ents', metadata, "'ents' must be "
		# 	    "defined for metadata %s" % metadata['name'])
		metadata_name = metadata['name']
		add_metadata_object_to_list(metadata, metadata_name)


# Preprocess top level metadata_tables. Add each entry to the metadata
# tables list
def preprocess_metadata_list(data):
	if 'metadata-list' not in data:
		return
	metadata_tables = data['metadata-list']

	for metadata in metadata_tables:
		check_exist('name', metadata, "'name' must be "
			    "defined for metadata")

		metadata_name = metadata['name']

		if 'list' in metadata:
			meta = [get_metadata_object(name)['object'] for name in metadata['list']]
			add_metadata_to_list(meta, metadata_name)
		else:
			check_exist('ents', metadata, "'ents' or 'list' must be "
					"defined for metadata %s" % metadata['name'])
			add_metadata_to_list(metadata['ents'], metadata_name)

# Preprocess top level tlv_nodes. Add each entry to the TLV nodes list
def preprocess_tlv_nodes(tlv_nodes):
	if 'tlv-nodes' not in data:
		return
	tlv_nodes = data['tlv-nodes']

	for tlv_node in tlv_nodes:
		check_exist('name', tlv_node, "'name' must be "
			    "defined for tlv-node")
		tlv_node_name = tlv_node['name']
		add_tlv_node_to_list(tlv_node, tlv_node_name)

		if 'overlay-node' in tlv_node:
			overlay_tlv = tlv_node['overlay-node']
			if 'ents' in overlay_tlv:
				table_name = "%s.tlv_overlay" % tlv_node_name
				add_table_to_list(overlay_tlv, table_name)

		if 'metadata' in tlv_node:
			metadata = tlv_node['metadata']
			if 'ents' in metadata:
				table_name = "%s.metadata" % tlv_node_name
				add_metadata_to_list(metadata['ents'],
						     table_name)

		if 'cond-exprs' in tlv_node:
			cond_exprs = tlv_node['cond-exprs']
			if 'ents' in cond_exprs:
				# Add embedded conditional expressions to
				# conditional expressions list
				table_name = "%s.cond_exprs" % parse_node_name
				add_cond_exprs_to_list(cond_exprs, table_name)

		if 'counter-actions' in tlv_node:
			ca = tlv_node['counter-actions']
			metadata = tlv_node['metadata']
			metadata_name = ("%s.metadata" % tlv_node_name) if 'ents' in metadata else metadata['list']
			add_counter_actions_to_metadata(ca, metadata_name)

# Preprocess top level flag_fields_nodes. Add each entry to the flag fields
# nodes list
def preprocess_flag_fields_nodes(data):
	if 'flag-fields-nodes' not in data:
		return
	flag_fields_nodes = data['flag-fields-nodes']

	for flag_fields_node in flag_fields_nodes:
		check_exist('name', flag_fields_node, "'name' must be "
			    "defined for flag-fields-node")
		flag_fields_node_name = flag_fields_node['name']
		add_flag_fields_node_to_list(flag_fields_node,
					     flag_fields_node_name)

		if 'metadata' in flag_fields_node:
			metadata = flag_fields_node['metadata']
			if 'ents' in metadata:
				table_name = "%s.metadata" % flag_fields_node_name
				add_metadata_to_list(metadata['ents'],
						     table_name)

		if 'cond-exprs' in flag_fields_node:
			cond_exprs = flag_fields_node['cond-exprs']
			if 'ents' in cond_exprs:
				# Add embedded conditional expressions to
				# conditional expressions list
				table_name = "%s.cond_exprs" % flag_fields_node_name
				add_cond_exprs_to_list(cond_exprs, table_name)

		if 'counter-actions' in flag_fields_node:
			ca = flag_fields_node['counter-actions']
			metadata = flag_fields_node['metadata']
			metadata_name = ("%s.metadata" % flag_fields_node_name) if 'ents' in metadata else metadata['list']
			add_counter_actions_to_metadata(ca, metadata_name)

# Preprocess top level flag_fields. Add each entry to the flag fields list
def preprocess_flag_fields(data):
	if 'flag-fields-tables' not in data:
		return
	flag_fields = data['flag-fields-tables']

	for flag_field in flag_fields:
		check_exist('name', flag_field, "'name' must be "
			    "defined for flag-fields-tables")
		check_exist('ents', flag_field, "'ents' must be "
			    "defined for flag-fields-tables %s" % flag_field['name'])
		flag_field_name = flag_field['name']
		add_flag_fields_to_list(flag_field['ents'], flag_field_name)

# Preprocess top level cond_exprs_tables. Add each entry to the conditional
# expressions list
def preprocess_cond_exprs_list(data):
	if 'cond-exprs-list' not in data:
		return
	cond_exprs_tables = data['cond-exprs-list']

	for cond_exprs in cond_exprs_tables:
		check_exist('name', cond_exprs, "'name' must be "
			    "defined for cond-exprs")
		check_exist('ents', cond_exprs, "'ents' must be "
			    "defined for cond-exprs %s" % cond_exprs['name'])
		cond_exprs_name = cond_exprs['name']
		add_cond_exprs_to_list(cond_exprs, cond_exprs_name)

# Program

n = len(sys.argv)
if n != 2:
	err("Usage: json2ipcmd <json-file>")

json_file = sys.argv[1]

f = open(json_file)

data = json.load(f)

preprocess_metadata_objects(data)
preprocess_metadata_list(data)
preprocess_cond_exprs_list(data)
preprocess_parsers(data)
preprocess_parse_nodes(data)
preprocess_proto_tables(data)
preprocess_tlv_nodes(data)
preprocess_flag_fields_nodes(data)
preprocess_flag_fields(data)

output_ipcmd_metadata()
output_ipcmd_cond_exprs()
output_ipcmd_tables()
output_ipcmd_flag_fields_tables()
output_ipcmd_parse_nodes()
output_ipcmd_tlv_nodes()
output_ipcmd_flag_fields_nodes()
output_ipcmd_table_ents()
output_ipcmd_flag_fields()
output_ipcmd_parsers()

print(outputbuf.getvalue(), end="")
