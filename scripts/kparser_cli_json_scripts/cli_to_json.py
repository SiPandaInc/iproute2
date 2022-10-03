#!/usr/bin/python3

## Load libraries
import json
import sys
import re
import argparse

## Arguments
parse = argparse.ArgumentParser()

parse.add_argument('--input',required=True,help="Name of the input file (CLI)")
parse.add_argument('--output',required=True,help="Name of the output file should be json")
parse.add_argument('--inline',default=0,type=int,help="Enable inline output with 1")

args = parse.parse_args()
file_name = args.input
char = []
text = ""
cov_data = []
output = args.output
output_file = open(output,'w')

parsers = []
parse_nodes = []
metadata_list = []
proto_tables = []
metadata_objects = []

## Functions for mapping Cli to Json 
node_next_proto_map = {
    'field-off':'field_off',
    'field-len':'field_len',
    'table':'table'
}
node_map = {
    'name':'name',
    'min-hdr-length':'min-hdr-length',
    'md':'metadata',
    'nxt': ['next_proto',node_next_proto_map]
}

def node_fun(dic):
    node = {}
    for f in node_map.keys():
        if f in dic['node']:
            target = node_map[f]
            if type(target) == str:
                if f == 'md':
                    node[target] = {"list":dic['node'][f]['ruleset']}
                else:
                    node[target] = dic['node'][f]
            else:
                next_proto = {}
                for np in node_next_proto_map.keys():
                    if np in dic['node'][f]:
                        next_proto[node_next_proto_map[np]] = dic['node'][f][np]
                node[target[0]] = next_proto
    parse_nodes.append(node)


parser_map = {
    'name':'name',
    'rootnode':'root-node'
}

def parser_fun(dic):
    parser = {}
    for f in parser_map.keys():
        if f in dic['parser']:
            parser[parser_map[f]] = dic['parser'][f]
    parsers.append(parser)

table_map = {
    'name':'name',
    'table':'name',
    'key':'key',
    'node':'node'
}

def table_fun(dic):
    table = {}
    ent_list = []
    ent = {}
    flag = 0
    for f in table_map.keys():
        if f in dic['table']:
            if f == 'name' or f=='table':
                for t in proto_tables:
                    if dic['table'][f] in t[table_map[f]]:
                        val = dic['table'][f]
                        flag = 1
                        break
                else:
                    table[table_map[f]] = dic['table'][f]
            else:
                ent[table_map[f]] = dic['table'][f]
    if ent:
        ent_list.append(ent)
        if flag == 1:
            for t in proto_tables:
                if t['name'] == val:
                    if 'ents' in t:
                        t['ents'].extend(ent_list)
                    else:
                        t['ents'] = ent_list
        else:
            table['ents'] = ent_list
    if table:
        if 'name' in table:
            proto_tables.append(table)
        else:
            pass

metadata_rule_map = {
    'name':'name',
    'type':'type',
    'addoff':'hdr-src-off',
    'md-off':'md-off'
}

def metadata_rule_fun(dic):
    metadata_rule = {}
    for f in metadata_rule_map.keys():
        if f in dic['metadata-rule']:
            metadata_rule[metadata_rule_map[f]] = dic['metadata-rule'][f]
    metadata_objects.append(metadata_rule)

metadata_ruleset_map = {
    'name':'name',
    'ents': 'list'
}

def metadata_ruleset_fun(dic):
    metalist = {}
    for f in metadata_ruleset_map.keys():
        if f in dic['metadata-ruleset']:
            metalist[metadata_ruleset_map[f]] = dic['metadata-ruleset'][f]
        if f == 'ents':
            e_l = []
            for e in dic['metadata-ruleset'][f]:
                e_l.append(list(list(list(e.values())[0].values())[0].values())[0])
            metalist[metadata_ruleset_map[f]] = e_l
    metadata_list.append(metalist)

## Functions for inlineing
def parser_node_inline(data):
    for node in data['parse-nodes']:
        if 'metadata' in node:
            mdl = [ele for ele in data['metadata-list'] if ele['name'] == node['metadata']]
            mdl_list = [ele['list'] for ele in mdl]
            node['metadata_list'] = mdl_list[0]
            node.pop('metadata', None)
        if 'next_proto' in node:
            if 'table' in node['next_proto']:
                ent = [ele for ele in data['proto-tables'] if ele['name'] == node['next_proto']['table']]
                ent_list = [ele['ent'] for ele in ent]
                node['next_proto']['ents'] = ent_list[0]
                node['next_proto'].pop('table', None)
    return data

def metadatalist_inline(data):
    for mdl in data['metadata-list']:
        l = []
        for md in mdl['list']:
            for ele in data['metadata-objects']:
                if ele['name'] == md:
                    l.append(ele)
        k = []
        for dic in l:
            dic_copy = dic.copy()
            dic_copy.pop('name', None)
            k.append(dic_copy)
        mdl['rules'] = k
        mdl.pop('list', None)
    return data

## Main 
with open(file_name,'r') as f:
    for line in f:
        line_format = " ".join(line.split())
        start_matched = [x for x in line_format if x == '[']
        char.extend(start_matched)
        if len(char) != 0:
            text = text + line
        end_matched = [x for x in line_format if x == ']']
        for c in end_matched:
            if c == ']':
                if char[-1] == '[':
                    char.pop()
                else:
                    sys.exit('Mismatched')
        if len(char) == 0:
            if len(text)>0:
                try:
                    data = json.loads(text)
                except:
                    pass
                if data[1]['execsummary']['opretcode'] == '0':
                    if int(data[1]['execsummary']['objectscounttotal']) > 1:
                        if 'ents' in data[3]:
                            cov_data.append(data[2])
                            list(list(cov_data[-1].values())[0].values())[0].update(data[3])
                        else:
                            cov_data.extend(data[2:])
                    else:
                        cov_data.append(data[2])
                for ele in cov_data:
                    dic = list(ele.values())[0]
                    if 'parser' in dic:
                        parser_fun(dic)
                    if 'metadata-ruleset' in dic:
                        metadata_ruleset_fun(dic)
                    if 'table' in dic:
                        table_fun(dic)
                    if 'metadata-rule' in dic:
                        metadata_rule_fun(dic)
                    if 'node' in dic:
                        node_fun(dic)
                cov_data = []
            text = ""


## Dump to json
cli_output = {
    'parsers' : parsers,
    'parse-nodes' : parse_nodes,
    'proto-tables' : proto_tables,
    'metadata-list' : metadata_list,
    'metadata-objects' : metadata_objects
}

inline = args.inline

## Inline output
if inline == 1:
    data_update = parser_node_inline(cli_output)
    data_update = metadatalist_inline(data_update)
    json.dump(data_update, output_file, indent=4)
else:
    json.dump(cli_output,output_file,indent=4)

output_file.close()
