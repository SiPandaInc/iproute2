# Convert a parser in .json representation to ipcmd parser commands
#
# Copyright SiPanda Inc., 2022
#

import json
import sys
from io import StringIO

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

# List of conditional expressions
cond_exprs_list = {}
cond_exprs_id = 0x2000

def add_cond_exprs_to_list(cond_exprs, name):
	global cond_exprs_list
	global cond_exprs_id

	check_list_not_exist(name, cond_exprs_list,
		"%s already in conditional expression list" % name)

	cond_exprs_list[name] = { "table": cond_exprs, "id": metadata_id }
	cond_exprs_id += 1

# List of flag fields nodes
flag_fields_node_list = {}
flag_fields_node_id = 0x2000

def add_flag_fields_node_to_list(flag_fields_node, name):
	global flag_fields_node_list
	global flag_fields_node_id

	check_list_not_exist(name, flag_fields_node_list,
		"%s already in flag fields node list" % name)

	flag_fields_node_list[name] = { "list": flag_fields_node,
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
				output("ipcmd parser create metadata-rule")
				name = "%s.%i" % (metadata_name, id)
				mylist.append(name)

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

				if 'length' not in instance:
					instance['length'] = 2 # default length for offset metadata
			elif type == 'bit_offset':
				check_exist('hdr-src-off', instance,
					    "'hdr-src-off' must defined for "
					    "hdrdata metadata %s" %
					    metadata_name)

				output(" type bit_offset addoff %s" % instance['hdr-src-off'])

				if 'length' not in instance:
					instance['length'] = 2 # default length for offset metadata
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

				output(" type %s constantvalue %s" % instance['value'])

			else:
				# Need to add other types of metadata
				err("Unknown metadata type %s" % type)

			# Destination offset in metadata structure
			check_exist('md-off', instance,
				    "'md-off' must defined for metadata %s" %
				     metadata_name)

			length = 'length' if type != 'nibb_extract' else 'nibb-length'

			# Length of data to write
			check_exist(length, instance,
				    "'%s' must defined for metadata %s" %
				     (length, metadata_name))

			outputnl(" md-off %s length %s" % (instance['md-off'],
						      instance[length]))

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
		outputnl("ipcmd parser create flagfields name %s" % table_name)
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
		cnt = 0
		for entry in table:
			check_exist('key', entry, "'key' must be defined for "
				    "entry in table %s" % table_name)
			check_exist('node', entry, "'node' must be defined for "
				    "entry in table %s" % table_name)
			output("ipcmd parser create table/%s/%d" %
			       (table_name, cnt))
			if 'name' in entry:
				output(" name %s.tabent.%s" %
				       (table_name, entry['name']))
			outputnl(" key %s node %s" %
			         (entry['key'], entry['node']))
			cnt += 1
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
			output("ipcmd parser create flagfield/%s/%d flag %s"
			       " field_length %s" %
			       (table_name, cnt, entry['flag'],
				entry['field-len']))
			cnt += 1
			if 'node' in entry:
				output(" node %s" % entry['node'])
			outputnl("")
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

# Output TLV parameters for a ipcmd command to create parse nodes
def output_ipcmd_node_tlv_node(tlv_parse_node, node_name):
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

	output(" tlvtable 0x%x" % table_id)

	if 'start_offset' in tlv_parse_node:
		output(" tlvstartoff %u" % tlv_parse_node['start_offset'])

	check_exist('data-offset', tlv_parse_node, "'data-offset' "
		    "must be defined for entry tlv-parse-node in %s" %
		     node_name)
	output(" tlvdataoff %u" % tlv_parse_node['data-offset'])

	check_exist('tlv-type', tlv_parse_node, "'tlv-type' "
		    "must be defined for tlv-parse-node in %s" % node_name)
	tlv_type = tlv_parse_node['tlv-type']
	check_exist('offset', tlv_type, "'offset' must be defined for "
		    "tlv-type in tlv-parse-node in %s" % node_name)
	check_exist('length', tlv_type, "'length' must be defined for "
		    "tlv-type in tlv-parse-node in %s" % node_name)
	output(" tlvtypeoff %u tlvtypelen %u" %
	       (tlv_type['offset'], tlv_type['length']))

	check_exist('tlv-length', tlv_parse_node, "'tlv-length' "
		    "must be defined for tlv-parse-node in %s" % node_name)
	tlv_length = tlv_parse_node['tlv-length']
	check_exist('offset', tlv_length, "'offset' must be defined for "
		    "tlv-length in tlv-parse-node in %s" % node_name)
	check_exist('length', tlv_length, "'length' must be defined for "
		    "tlv-length in tlv-parse-node in %s" % node_name)
	output(" tlvlenoff %u tlvlenlen %u" %
	       (tlv_length['offset'], tlv_length['length']))

	if 'pad1' in tlv_parse_node:
		output(" tlvpad1 %u" % tlv_parse_node['pad1'])

	if 'eol' in tlv_parse_node:
		output(" tlveol %u" % tlv_parse_node['eol'])

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
	table_id = flag_fields_list[table_name]['id']

	output(" flag_fields 0x%x" % table_id)

	check_exist('flags-offset', flag_fields_parse_node,
		    "'flags-offset' must be defined for "
		    "flag-fields-parse-node %s" % node_name)
	check_exist('flags-length', flag_fields_parse_node,
		    "'flags-length' must be defined for "
		    "flag-fields-parse-node %s" % node_name)

	output(" flagsoff %u flagslen %u" %
	       (flag_fields_parse_node['flags-offset'],
		flag_fields_parse_node['flags-length']))

	if 'flags-mask' in flag_fields_parse_node:
		output(" flagsmask %s" % flag_fields_parse_node['flags-mask'])

	if 'hdr-length' in flag_fields_parse_node:
		if 'hdr-length' in node:
			err("'hdr_len' cannot be in both a parse node and its "
			    "flag-fields-parse-node")
		hdr_length = flag_fields_parse_node['hdr-length']
		if 'flag-fields-length' in hdr_length and \
		    hdr_length['flag-fields-length']:
			output(" hdrlenflags")

def output_parse_node(node_name, node, id):
	output("ipcmd parser create node name %s" % node_name)
	check_exist('min-hdr-length', node, "'min-hdr-length' must be defined for "
		    "parse_node %s" % node_name)
	output(" minlen %s" % node['min-hdr-length'])
	if 'hdr-length' in node: # Variable length header
		hdr_length = node['hdr-length']
		check_exist('field-off', hdr_length, "'field-off' must be defined "
			    "for hdr-length in parse-node in %s" % node_name)
		check_exist('field-len', hdr_length, "'field-len' must be defined "
			    "for hdr-length in parse-node in %s" % node_name)
		output(" hdrlenoff %u hdrlenlen %u" %
		       (hdr_length['field-off'], hdr_length['field-len']))
		if 'mask' in hdr_length:
			output(" hdrlenmask %s" % hdr_length['mask'])
		if 'multiplier' in hdr_length:
			output(" hdrlenmult %u" % hdr_length['multiplier'])
		if 'add' in hdr_length:
			output(" hdrlenadd %u" % hdr_length['add'])

	if 'next-proto' in node: # Non-leaf node
		next_proto = node['next-proto']
		check_exist('field-off', next_proto, "'field-off' must be defined "
			    "for next-proto in parse-node in %s" % node_name)
		check_exist('field-len', next_proto, "'field-len' must be defined "
			    "for next-proto in parse-node in %s" % node_name)
		if 'ents' in next_proto:
			table_name = "%s.next_proto" % node_name
		elif 'table' in next_proto:
			table_name = next_proto['table']
		else:
			err("No ents or table in next proto")

		check_exist(table_name, table_list,
			    "Cannot find table %s for parse node "
			    "%s" % (table_name, node_name))
		table_id = table_list[table_name]['id']

		output(" nxtoffset %u nxtlength %u" %
		       (next_proto['field-off'], next_proto['field-len']))
		output(" prottable 0x%x" % table_id)

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

	if tlv_node_list == {}:
		return

	outputnl("# Create TLV nodes")

	for tlv_node_name in tlv_node_list:
		id = tlv_node_list[tlv_node_name]['id']
		tlv_node = tlv_node_list[tlv_node_name]['node']
		output("ipcmd parser create tlvnode name %s" % tlv_node_name)

		if 'overlay-node' in tlv_node:
			overlay_tlv = tlv_node['overlay-node']
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

			output(" overlaytable 0x%x" % table_id)

		if 'metadata' in tlv_node:
			output_ipcmd_node_metadata(tlv_node['metadata'],
					     tlv_node_name)

		outputnl("")
	outputnl("")

# Output ipcmd commands to create conditional expression. Read the global
# conditional expressions list and output a create command for each entry
def output_ipcmd_cond_exprs():
	global cond_exprs_list

	if cond_exprs_list == {}:
		return

	outputnl("# Create conditional expression and lists")

	for cond_exprs_name in cond_exprs_list:
		cond_exprs = cond_exprs_list[cond_exprs_name]['table']
		mid = cond_exprs_list[cond_exprs_name]['id']
		id = mid + 1
		mylist = []
		for instance in cond_exprs['ents']:
			# Create each instance of conditional expression
			if 'name' in instance:
				iname = instance['name']
				name = "%s.%s" % (cond_exprs_name, iname)
				output("ipcmd parser create cond-exprs name %s" % name)
			else:
				iname = "<unnamed>"
				output("ipcmd parser create cond-exprs")

			check_exist('type', instance, "'type' must be defined "
				    "for conditional expression %s" % iname)
			check_exist('field-off', instance, "'field-off' must be "
				    "defined for conditional expression %s" %
				    iname)
			check_exist('field-len', instance, "'field-len' must be "
				    "defined for conditional expression %s" %
				     iname)
			check_exist('value', instance, "'value' must be "
				    "defined for conditional expression %s" %
				    iname)

			output(" type %s src_off %d length %d value %s" %
			       (instance['type'], instance['field-off'],
			        instance['field-len'], instance['value']))

			if 'mask' in instance:
				output(" mask %s" % instance['mask'])

			mylist.append(id)
			id += 1
			outputnl("")

		if mylist != []:
			# Create a metalist for this set of metadata
			output("ipcmd parser create cond_exprs_list name %s "
					% cond_exprs_name)

			if 'type' in cond_exprs:
				output(" type %s" % cond_exprs['type'])
			elif len(mylist) != 1:
				err("Need type (and, or) in conditional "
				    "expression")

			for i in mylist:
				output(" cond_exprs_list 0x%x" % i)
			outputnl("")
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
		output(" root_node %s" % parser['root-node'])
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
	return

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

preprocess_parsers(data)
preprocess_parse_nodes(data)
preprocess_proto_tables(data)
preprocess_tlv_nodes(data)
preprocess_flag_fields_nodes(data)
preprocess_flag_fields(data)
preprocess_metadata_objects(data)
preprocess_metadata_list(data)
preprocess_cond_exprs_list(data)

output_ipcmd_metadata()
output_ipcmd_tables()
output_ipcmd_flag_fields_tables()
output_ipcmd_cond_exprs()
output_ipcmd_parse_nodes()
output_ipcmd_tlv_nodes()
output_ipcmd_table_ents()
output_ipcmd_flag_fields()
output_ipcmd_parsers()

print(outputbuf.getvalue(), end="")
