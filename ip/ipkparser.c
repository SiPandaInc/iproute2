/*
 * kparser.c	Panda Parser in Kernel
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:	Pratyush Khan <pratyush@sipanda.io>
 */

#include <stdbool.h>
#include <linux/types.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <linux/kparser.h>
#include <linux/genetlink.h>
#include <linux/ip.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libgenl.h"
#include "utils.h"
#include "ip_common.h"
#include "json_print.h"


// TODO:
// Follow usage format from other places
// dont use KP, use KPARSER

static void usage(void)
{
	fprintf(stderr,
		"Usage: ip kparser [cmd CMDS] name big_parser id 0x1000 root_node ether\n"
		"CMDS := [ {create | modify | list | delete} ]\n"
		"           \n");

	exit(-1);
}

/* netlink socket */
static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

#define KPARSER_REQUEST(_req, _bufsiz, _cmd, _flags)			\
	GENL_REQUEST(_req, _bufsiz, genl_family, 0,			\
		     KPARSER_GENL_VERSION, _cmd, _flags)

#define KPARSER_NLM_MAX_LEN 1024

// TODO: convert these macros to inline fns
#define PARSE_CMD_LINE_KEY_VAL_STR(key, value, maxlen)			\
do {									\
	const char *str_arg_ptr;					\
	parsed = false;							\
	if (argc == 0 || argv[argidx] == NULL) {			\
		if (optional == false) {				\
			fprintf(stderr, "Key `%s` empty!\n", key);	\
			rc = -EINVAL;					\
			goto einval_out;				\
		}							\
		break;							\
	}								\
	if (matches(argv[argidx++], key) != 0) {			\
		if (optional == false) {				\
			fprintf(stderr, "Key `%s` missing!\n", key);	\
			rc = -EINVAL;					\
			goto einval_out;				\
		}							\
		break;							\
	}								\
	argc--;								\
	str_arg_ptr = argv[argidx++];					\
	if (str_arg_ptr == NULL) {					\
		fprintf(stderr, "Expected value after key `%s`\n", key);\
		rc = -EINVAL;						\
		goto einval_out;					\
	}								\
	argc--;								\
	if (strlen(str_arg_ptr) > maxlen) {				\
		fprintf(stderr,						\
			"Value `%s` of key `%s` exceeds max len %lu\n",	\
			str_arg_ptr, key, (size_t) maxlen);		\
		rc = -EINVAL;						\
		goto einval_out;					\
	}								\
	(void) strncpy(value, str_arg_ptr, maxlen);			\
	parsed = true;							\
} while (0)

#define PARSE_CMD_LINE_KEY_VAL_U64(key, value, min, max)		\
do {									\
	char arg_val[KPARSER_MAX_U64_STR_LEN];				\
	int32_t errno_local;						\
	uint64_t ret_digit;						\
	PARSE_CMD_LINE_KEY_VAL_STR(key, arg_val, sizeof(arg_val));	\
	if (parsed == false)						\
		break;							\
	ret_digit = strtoull(arg_val, NULL, 0);				\
	errno_local = errno;						\
	if (errno_local == EINVAL || errno_local == ERANGE) {		\
		fprintf(stderr, "Expected u16 digit for Key `%s`."	\
				"errno: %d in strtoull().Try again.\n",	\
				key, errno_local);			\
		rc = -EINVAL;						\
		goto einval_out;					\
	}								\
	if (ret_digit > max || ret_digit < min) {			\
		fprintf(stderr, "Value %lu for Key `%s` is out of valid"\
				"range. Min: %d, Max: %d.Try again.\n",	\
				ret_digit, key, min, max);		\
		rc = -EINVAL;						\
		goto einval_out;					\
	}								\
	value = ret_digit;						\
} while (0)

#define PARSE_CMD_LINE_KEY_VAL_U16(key, value, min, max)		\
do {									\
	char arg_val[KPARSER_MAX_U16_STR_LEN];				\
	int32_t errno_local;						\
	uint64_t ret_digit;						\
	PARSE_CMD_LINE_KEY_VAL_STR(key, arg_val, sizeof(arg_val));	\
	if (parsed == false)						\
		break;							\
	ret_digit = strtoull(arg_val, NULL, 0);				\
	errno_local = errno;						\
	if (errno_local == EINVAL || errno_local == ERANGE) {		\
		fprintf(stderr, "Expected u16 digit for Key `%s`."	\
				"errno: %d in strtoull().Try again.\n",	\
				key, errno_local);			\
		rc = -EINVAL;						\
		goto einval_out;					\
	}								\
	if (ret_digit > max || ret_digit < min) {			\
		fprintf(stderr, "Value %lu for Key `%s` is out of valid"\
				"range. Min: %d, Max: %d.Try again.\n",	\
				ret_digit, key, min, max);		\
		rc = -EINVAL;						\
		goto einval_out;					\
	}								\
	value = (u16) ret_digit;					\
} while (0)

#define PARSE_CMD_LINE_HKEY(name_k, name_v, id_k, id_v)			\
do {									\
	PARSE_CMD_LINE_KEY_VAL_STR(name_k, name_v, sizeof(name_v));	\
	PARSE_CMD_LINE_KEY_VAL_U16(id_k, id_v, 0, KPARSER_INVALID_ID - 1); \
} while (0)

// TODO: use spaces while using arithmatic operators

static int32_t exec_cmd(uint8_t cmd, int32_t req_attr, int32_t rsp_attr,
		const void *cmd_arg, size_t cmd_arg_size,
		void *rsp_buf, size_t rsp_buf_size)
{
	struct rtattr *tb[KPARSER_ATTR_MAX + 1];
	struct nlmsghdr *answer;
	struct genlmsghdr *ghdr;
	int32_t len;
	int32_t rc;

	KPARSER_REQUEST(req, KPARSER_NLM_MAX_LEN, cmd, NLM_F_REQUEST);
	rc = addattr_l(&req.n, KPARSER_NLM_MAX_LEN, req_attr,
			cmd_arg, cmd_arg_size);
	if (rc != 0) {
		fprintf(stderr, "addattr_l() failed, cmd:%u attr:%d rc:%d\n",
				cmd, req_attr, rc);
		return rc;
	}

	rc = rtnl_talk(&genl_rth, &req.n, &answer);
	if (rc != 0) {
		fprintf(stderr, "rtnl_talk() failed, cmd:%u attr:%d rc:%d\n",
				cmd, req_attr, rc);
		return rc;
	}

	len = answer->nlmsg_len;

	if (answer->nlmsg_type != genl_family) {
		fprintf(stderr, "family type err, expected: %d, found:%u\n",
				genl_family, answer->nlmsg_type);
		return -1;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		fprintf(stderr, "rsp len err: %d\n", len);
		return -1;
	}

	ghdr = NLMSG_DATA(answer);
	rc = parse_rtattr(tb, KPARSER_ATTR_MAX, (void *) ghdr + GENL_HDRLEN, len);
	if (rc < 0) {
		fprintf(stderr, "parse_rtattr() err, rc:%d\n", rc);
		return rc;
	}

	if (tb[rsp_attr]) {
		if (RTA_PAYLOAD(tb[rsp_attr]) < rsp_buf_size) {
			fprintf(stderr, "for attr:%d, rsp size: %lu is"
					" smaller than expected size:%lu\n",
					rsp_attr, RTA_PAYLOAD(tb[rsp_attr]),
					rsp_buf_size);
			return -1;
		}
		memcpy(rsp_buf, RTA_DATA(tb[rsp_attr]), rsp_buf_size);
	}

	return 0;
}

static int do_create_metadata(int argc, const char **argv)
{
	struct kparser_cmd_rsp_hdr cmd_rsp;
	struct kparser_arg_md cmd_arg;
	bool optional = false;
	int32_t argidx = 0;
	bool parsed;
	int32_t rc;

	memset(&cmd_arg, 0, sizeof(cmd_arg));

	PARSE_CMD_LINE_HKEY("name", cmd_arg.key.name, "id", cmd_arg.key.id);
	// use lower case hex numbers
	PARSE_CMD_LINE_KEY_VAL_U16("soff", cmd_arg.soff, 0, 0xfffe);
	PARSE_CMD_LINE_KEY_VAL_U16("doff", cmd_arg.doff, 0, 0xfffe);
	PARSE_CMD_LINE_KEY_VAL_U64("len", cmd_arg.len, 0, 0xffff);

	fprintf(stdout, "%s: key:{%s:%u}, soff:%u doff:%u len:%lu\n",
			__FUNCTION__, cmd_arg.key.name,cmd_arg.key.id,
			cmd_arg.soff, cmd_arg.doff, cmd_arg.len);

	rc = exec_cmd(KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_MD,
			KPARSER_ATTR_CREATE_MD_RSP,
			&cmd_arg, sizeof(cmd_arg),
			&cmd_rsp, sizeof(cmd_rsp));
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				__FUNCTION__,
				KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_MD,
				KPARSER_ATTR_CREATE_MD_RSP, rc);
		return rc;
	}

	fprintf(stdout, "%s:cmd %d executed for attrs:{%d:%d}, op rc:[%d:%s]\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_MD,
			KPARSER_ATTR_CREATE_MD_RSP,
			cmd_rsp.op_ret_code, cmd_rsp.err_str_buf);
	return 0;

einval_out:
	fprintf(stderr, "%s:cmd %d didn't execute for attrs:{%d:%d}, rc:%d\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_MD,
			KPARSER_ATTR_CREATE_MD_RSP, rc);
	return rc;
}

static int do_create_metadata_list(int argc, const char **argv)
{
	struct kparser_cmd_rsp_hdr cmd_rsp;
	struct kparser_arg_mdl *cmd_arg;
	size_t total_mdkeys_ptr_len;
	bool optional = false;
	int32_t argidx = 0;
	struct kparser_hkey mdkey;
	void *mdkeys_ptr;
	bool parsed;
	int32_t rc;
	int32_t idx;

	mdkeys_ptr = calloc(1, sizeof(*cmd_arg));
	if (mdkeys_ptr == NULL) {
		fprintf(stderr, "%s: calloc() failed for size:%lu\n",
				__FUNCTION__, sizeof(*cmd_arg));
		return -ENOMEM;
	}
	cmd_arg = mdkeys_ptr;
	total_mdkeys_ptr_len = sizeof(*cmd_arg);
	PARSE_CMD_LINE_HKEY("name", cmd_arg->key.name, "id", cmd_arg->key.id);
	PARSE_CMD_LINE_HKEY("metadata.name", cmd_arg->mdkey.name,
			"metadata.id", cmd_arg->mdkey.id);
	cmd_arg->mdkeys_count = 0;
	
	optional = true;
	
	while (1) {
		PARSE_CMD_LINE_HKEY("metadata.name", mdkey.name,
				"metadata.id", mdkey.id);
		if (parsed == false)
			break;
		total_mdkeys_ptr_len += sizeof(mdkey);
		mdkeys_ptr = realloc(mdkeys_ptr, total_mdkeys_ptr_len);
		if (mdkeys_ptr == NULL) {
			fprintf(stderr, "%s: realloc() failed for size:%lu\n",
					__FUNCTION__, total_mdkeys_ptr_len);
			return -ENOMEM;
		}
		cmd_arg = mdkeys_ptr;
		cmd_arg->mdkeys[cmd_arg->mdkeys_count++] = mdkey;
	}

	fprintf(stdout, "%s: key:{%s:%u}, MMD_K:{%s:%u}, key_cnt:%u\n",
			__FUNCTION__, cmd_arg->key.name,cmd_arg->key.id,
			cmd_arg->mdkey.name, cmd_arg->mdkey.id,
			cmd_arg->mdkeys_count);

	for(idx = 0; idx < cmd_arg->mdkeys_count; idx++)
		fprintf(stdout, "Idx:%d MDkey:{%s:%u}\n", idx,
				cmd_arg->mdkeys[idx].name,
				cmd_arg->mdkeys[idx].id);

	rc = exec_cmd(KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_MDL,
			KPARSER_ATTR_CREATE_MDL_RSP,
			cmd_arg, total_mdkeys_ptr_len,
			&cmd_rsp, sizeof(cmd_rsp));
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				__FUNCTION__,
				KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_MDL,
				KPARSER_ATTR_CREATE_MDL_RSP, rc);
		return rc;
	}

	fprintf(stdout, "%s:cmd %d executed for attrs:{%d:%d}, op rc:[%d:%s]\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_MDL,
			KPARSER_ATTR_CREATE_MDL_RSP,
			cmd_rsp.op_ret_code, cmd_rsp.err_str_buf);
	return 0;

einval_out:
	fprintf(stderr, "%s:cmd %d didn't execute for attrs:{%d:%d}, rc:%d\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_MDL,
			KPARSER_ATTR_CREATE_MDL_RSP, rc);
	return rc;
}

static int do_create_node(int argc, const char **argv)
{
	struct kparser_cmd_rsp_hdr cmd_rsp;
	struct kparser_arg_node cmd_arg;
	bool optional = false;
	int32_t argidx = 0;
	bool parsed;
	int32_t rc;

	memset(&cmd_arg, 0, sizeof(cmd_arg));

	PARSE_CMD_LINE_HKEY("name", cmd_arg.key.name, "id", cmd_arg.key.id);
	PARSE_CMD_LINE_KEY_VAL_U16("minlen", cmd_arg.minlen, 0, 0xFFFE);
	cmd_arg.type = KPARSER_NODE_TYPE_PROTO;
	cmd_arg.mdl_key.id = KPARSER_INVALID_ID;
	cmd_arg.prot_tbl_key.id = KPARSER_INVALID_ID;
	optional = true;
	PARSE_CMD_LINE_KEY_VAL_U16("nxtoffset", cmd_arg.nxtoffset, 0, 0xFFFE);
	if (parsed) {
		optional = false;
		PARSE_CMD_LINE_KEY_VAL_U16("nxtlength", cmd_arg.nxtlength,
				0, 0xFFFE);
		PARSE_CMD_LINE_HKEY("prottable.name",
				cmd_arg.prot_tbl_key.name,
				"prottable.id", cmd_arg.prot_tbl_key.id);
		PARSE_CMD_LINE_HKEY("metadata_list.name", cmd_arg.mdl_key.name,
				"metadata_list.id", cmd_arg.mdl_key.id);
		cmd_arg.type = KPARSER_NODE_TYPE_PARSER;
	}

	fprintf(stdout, "%s: key:{%s:%u}, minlen:%u\n",
			__FUNCTION__, cmd_arg.key.name,cmd_arg.key.id,
			cmd_arg.minlen);

	switch(cmd_arg.type) {
	case KPARSER_NODE_TYPE_PARSER:
		fprintf(stdout, "%s: nxtoffset:%u nxtlength:%u,"
				"proto_tbl_key:{%s:%u}, md_list_key:{%s:%u}\n",
				__FUNCTION__, cmd_arg.nxtoffset,
				cmd_arg.nxtlength,
				cmd_arg.prot_tbl_key.name,
				cmd_arg.prot_tbl_key.id,
				cmd_arg.mdl_key.name,
				cmd_arg.mdl_key.id);
		break;
	default:
		break;
	}
	
	rc = exec_cmd(KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_NODE,
			KPARSER_ATTR_CREATE_NODE_RSP,
			&cmd_arg, sizeof(cmd_arg),
			&cmd_rsp, sizeof(cmd_rsp));
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				__FUNCTION__,
				KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_NODE,
				KPARSER_ATTR_CREATE_NODE_RSP, rc);
		return rc;
	}

	fprintf(stdout, "%s:cmd %d executed for attrs:{%d:%d}, op rc:[%d:%s]\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_NODE,
			KPARSER_ATTR_CREATE_NODE_RSP,
			cmd_rsp.op_ret_code, cmd_rsp.err_str_buf);
	return 0;

einval_out:
	fprintf(stderr, "%s:cmd %d didn't execute for attrs:{%d:%d}, rc:%d\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_PARSER,
			KPARSER_ATTR_CREATE_PARSER_RSP, rc);
	return rc;
}

static int do_create_proto_table_entry(int argc, const char **argv)
{
	struct kparser_cmd_rsp_hdr cmd_rsp;
	struct kparser_arg_proto_tbl cmd_arg;
	char arg_u16[KPARSER_MAX_U16_STR_LEN];
	bool optional = false;
	const char *tk, *tk1;
	uint64_t ret_digit;
	int32_t errno_local;
	int32_t argidx = 0;
	bool parsed;
	int32_t rc;

	memset(&cmd_arg, 0, sizeof(cmd_arg));

	// parsing pattern: "table/ether:0x402/1"
	tk = strchr((const char *) *argv, '/');
	tk++;
	tk1 = strchr(tk, ':');
	if (tk1 == NULL) {
		fprintf(stderr, "%s:Create table entry command's format is "
				"\"table/<table_name>:<table_id>/<table_idx>\"."
				"Here ':' is missing around \"%s\".\n",
				__FUNCTION__, tk);
		return -EINVAL;
	}
	tk1--;
	if ((tk1 - tk)+1 > sizeof(cmd_arg.key.name)) {
		fprintf(stderr, "%s:Create table entry command's table"
				" key name len is %ld, but max allowed key"
				" name len is %lu\n",
				__FUNCTION__,(tk1 - tk)+1,sizeof(cmd_arg.key.name));
		return -EINVAL;
	}
	strncpy(cmd_arg.key.name, tk, tk1 - tk+1);
	cmd_arg.key.name[(tk1 - tk) + 1] = '\0';
	tk1+=2;
	if (tk1 >= *argv + strlen(*argv)) {
		fprintf(stderr, "%s:Create table entry command's format is "
				"\"table/<table_name>:<table_id>/<table_idx>\"."
				"Here input required after table key name \"%s\"\n",
				__FUNCTION__, cmd_arg.key.name);
		return -EINVAL;
	}
	tk = strchr(tk1, '/');
	if (tk1 == NULL) {
		fprintf(stderr, "%s:Create table entry command's format is "
				"\"table/<table_name>:<table_id>/<table_idx>\"."
				"Here last '/' is missing around \"%s\".\n",
				__FUNCTION__, tk);
		return -EINVAL;
	}
	tk--;
	if ((tk - tk1)+1 > sizeof(arg_u16)) {
		fprintf(stderr, "%s:Create table entry command's table"
				" key name id's length %ld, but max allowed key"
				" id len is %lu\n",
				__FUNCTION__,(tk - tk1)+1,sizeof(arg_u16));
		return -EINVAL;
	}
	strncpy(arg_u16, tk1, tk - tk1+1);
	arg_u16[(tk - tk1) + 1] = '\0';
	tk+=2;
	if (tk >= *argv + strlen(*argv)) {
		fprintf(stderr, "%s:Create table entry command's format is "
				"\"table/<table_name>:<table_id>/<table_idx>\"."
				"Here input required after table key id \"%s\"\n",
				__FUNCTION__, arg_u16);
		return -EINVAL;
	}
	ret_digit = strtoull(arg_u16, NULL, 0);	
	errno_local = errno;
	if (errno_local == EINVAL || errno_local == ERANGE) {
		fprintf(stderr, "Expected u16 digit for table key id,"
				"errno: %d in strtoull().Try again.\n",
				errno_local);
		return -EINVAL;
	}
	if (ret_digit >= KPARSER_INVALID_ID) {
		fprintf(stderr, "Value %lu for table key id is out of valid"
				"range. Min: 0, Max: %d.Try again.\n",
				ret_digit, KPARSER_INVALID_ID);
		return -EINVAL;
	}
	cmd_arg.key.id = (uint16_t) ret_digit;

	tk1 = *argv + strlen(*argv);
	if ((tk1 - tk)+1 > sizeof(arg_u16)) {
		fprintf(stderr, "%s:Create table entry command's table"
				" key index's length is %ld, but max allowed key"
				" index len is %lu\n",
				__FUNCTION__,(tk1 - tk)+1,sizeof(arg_u16));
		return -EINVAL;
	}
	strncpy(arg_u16, tk, tk1 - tk+1);
	arg_u16[(tk1 - tk) + 1] = '\0';
	ret_digit = strtoull(arg_u16, NULL, 0);	
	errno_local = errno;
	if (errno_local == EINVAL || errno_local == ERANGE) {
		fprintf(stderr, "Expected u16 digit for table key idx,"
				"errno: %d in strtoull().Try again.\n",
				errno_local);
		return -EINVAL;
	}
	if (ret_digit >= KPARSER_INVALID_ID) {
		fprintf(stderr, "Value %lu for table key idx is out of valid"
				"range. Min: 0, Max: %d.Try again.\n",
				ret_digit, KPARSER_INVALID_ID);
		return -EINVAL;
	}
	cmd_arg.tbl_ent.idx_key_map = (uint16_t) ret_digit;

	argc--;
	argv++;

	PARSE_CMD_LINE_HKEY("name", cmd_arg.tbl_ent.key.name,
			"key", cmd_arg.tbl_ent.key.id);

	// TODO:
	u16 t = cmd_arg.tbl_ent.key.id;
	cmd_arg.tbl_ent.key.id = cmd_arg.tbl_ent.idx_key_map;
	cmd_arg.tbl_ent.idx_key_map = t;

	if (argc && matches(argv[argidx], "node") != 0) {
		fprintf(stderr, "%s: Expected key \"node\" here after previous"
				" key value\n", __FUNCTION__);
		return -EINVAL;
	}
	argc--;
	argidx++;


	PARSE_CMD_LINE_HKEY("name", cmd_arg.tbl_ent.node_key.name,
			"id", cmd_arg.tbl_ent.node_key.id);

	fprintf(stdout, "%s: Tbl key:{%s:%u}, idx: %u entry key:{%s:%u}"
			"node_key:{%s:%u}\n",
			__FUNCTION__,
			cmd_arg.key.name, cmd_arg.key.id,
			cmd_arg.tbl_ent.idx_key_map,
			cmd_arg.tbl_ent.key.name, cmd_arg.tbl_ent.key.id,
			cmd_arg.tbl_ent.node_key.name,
			cmd_arg.tbl_ent.node_key.id);

	rc = exec_cmd(KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_TBL_ENT,
			KPARSER_ATTR_CREATE_TBL_ENT_RSP,
			&cmd_arg, sizeof (cmd_arg),
			&cmd_rsp, sizeof(cmd_rsp));
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				__FUNCTION__,
				KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_TBL_ENT,
				KPARSER_ATTR_CREATE_TBL_ENT_RSP, rc);
		return rc;
	}

	fprintf(stdout, "%s:cmd %d executed for attrs:{%d:%d}, op rc:[%d:%s]\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_TBL_ENT,
			KPARSER_ATTR_CREATE_TBL_ENT_RSP,
			cmd_rsp.op_ret_code, cmd_rsp.err_str_buf);
	return 0;

einval_out:
	fprintf(stderr, "%s:cmd %d didn't execute for attrs:{%d:%d}, rc:%d\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_TBL_ENT,
			KPARSER_ATTR_CREATE_TBL_ENT_RSP, rc);
	return rc;
}

static int do_create_proto_table(int argc, const char **argv)
{
	struct kparser_arg_proto_tbl cmd_arg;
	struct kparser_cmd_rsp_hdr cmd_rsp;
	bool optional = false;
	int32_t argidx = 0;
	char def_val[64];
	bool parsed;
	int32_t rc;

	memset(&cmd_arg, 0, sizeof(cmd_arg));

	PARSE_CMD_LINE_HKEY("name", cmd_arg.key.name, "id", cmd_arg.key.id);
	PARSE_CMD_LINE_KEY_VAL_STR("default", def_val, sizeof (def_val));
	if(strcmp(def_val, "stop_okay")) {
		fprintf(stderr, "%s:proto tbl only accepts default value:"
				"\"stop_okay\", but found value: \"%s\"."
				"Try again.\n", __FUNCTION__, def_val);
		return -EINVAL;
	}
	cmd_arg.def_val = KPARSER_STOP_OKAY;
	PARSE_CMD_LINE_KEY_VAL_U16("size", cmd_arg.tbl_ents_cnt, 0, 0xFFFF);

	fprintf(stdout, "%s: key:{%s:%u}, default_val:%u entry_count:%u\n",
			__FUNCTION__, cmd_arg.key.name,cmd_arg.key.id,
			cmd_arg.def_val, cmd_arg.tbl_ents_cnt);

	rc = exec_cmd(KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_TBL,
			KPARSER_ATTR_CREATE_TBL_RSP,
			&cmd_arg, sizeof(cmd_arg),
			&cmd_rsp, sizeof(cmd_rsp));
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				__FUNCTION__,
				KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_TBL,
				KPARSER_ATTR_CREATE_TBL_RSP, rc);
		return rc;
	}

	fprintf(stdout, "%s:cmd %d executed for attrs:{%d:%d}, op rc:[%d:%s]\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_TBL,
			KPARSER_ATTR_CREATE_TBL_RSP,
			cmd_rsp.op_ret_code, cmd_rsp.err_str_buf);
	return 0;

einval_out:
	fprintf(stderr, "%s:cmd %d didn't execute for attrs:{%d:%d}, rc:%d\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_TBL,
			KPARSER_ATTR_CREATE_TBL_RSP, rc);
	return rc;
}

static int32_t do_create_parser(int32_t argc, const char **argv)
{
	struct kparser_cmd_rsp_hdr cmd_rsp;
	struct kparser_arg_parser cmd_arg;
	bool optional = false;
	int32_t argidx = 0;
	bool parsed;
	int32_t rc;

	memset(&cmd_arg, 0, sizeof(cmd_arg));

	PARSE_CMD_LINE_HKEY("name", cmd_arg.key.name, "id", cmd_arg.key.id);
	PARSE_CMD_LINE_HKEY("root_node_name", cmd_arg.root_node_key.name,
			"root_node_id", cmd_arg.root_node_key.id);

	fprintf(stdout, "%s: key:{%s:%u}, root_node_key{%s:%u}\n",
			__FUNCTION__, cmd_arg.key.name, cmd_arg.key.id,
			cmd_arg.root_node_key.name, cmd_arg.root_node_key.id);

	rc = exec_cmd(KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_PARSER,
			KPARSER_ATTR_CREATE_PARSER_RSP,
			&cmd_arg, sizeof(cmd_arg),
			&cmd_rsp, sizeof(cmd_rsp));
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				__FUNCTION__,
				KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_PARSER,
				KPARSER_ATTR_CREATE_PARSER_RSP, rc);
		return rc;
	}

	fprintf(stdout, "%s:cmd %d executed for attrs:{%d:%d}, op rc:[%d:%s]\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_PARSER,
			KPARSER_ATTR_CREATE_PARSER_RSP,
			cmd_rsp.op_ret_code, cmd_rsp.err_str_buf);
	return 0;

einval_out:
	fprintf(stderr, "%s:cmd %d didn't execute for attrs:{%d:%d}, rc:%d\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_CREATE_PARSER,
			KPARSER_ATTR_CREATE_PARSER_RSP, rc);
	return rc;
}

static int do_create(int argc, const char **argv)
{
	const char *tk;

	if (argc && matches(*argv, "metadata") == 0)
		return do_create_metadata(argc-1, argv+1);

	if (argc && matches(*argv, "metalist") == 0)
		return do_create_metadata_list(argc-1, argv+1);

	if (argc && matches(*argv, "node") == 0)
		return do_create_node(argc-1, argv+1);

	if (argc && matches(*argv, "table") == 0)
		return do_create_proto_table(argc-1, argv+1);

	if (argc && matches(*argv, "parser") == 0)
		return do_create_parser(argc-1, argv+1);

	if (argc) {
		tk = strchr(*argv, '/');
		if ((tk != NULL) && (strncmp(*argv, "table", tk - *argv + 1)))
			return do_create_proto_table_entry(argc, argv);
	}

	fprintf(stderr, "Invalid key: %s. Valid keywords after \"create\" are:"
			"[{parser | metadata | metalist | node | table}]\n",
			*argv);
	return -EINVAL;
}

static int32_t do_delete(int32_t argc, const char **argv)
{
	struct kparser_cmd_rsp_hdr cmd_rsp;
	int32_t rc;

	rc = exec_cmd(KPARSER_CMD_ADD, KPARSER_ATTR_DELL_ALL,
			KPARSER_ATTR_DELL_ALL_RSP,
			NULL, 0,
			&cmd_rsp, sizeof(cmd_rsp));
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				__FUNCTION__,
				KPARSER_CMD_ADD, KPARSER_ATTR_DELL_ALL,
				KPARSER_ATTR_DELL_ALL_RSP, rc);
		return rc;
	}

	fprintf(stdout, "%s:cmd %d executed for attrs:{%d:%d}, op rc:[%d:%s]\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_DELL_ALL,
			KPARSER_ATTR_DELL_ALL,
			cmd_rsp.op_ret_code, cmd_rsp.err_str_buf);
	return 0;
}

static int32_t do_list(int32_t argc, const char **argv)
{
	struct kparser_cmd_rsp_hdr cmd_rsp;
	struct kparser_hkey cmd_arg;
	bool optional = false;
	int32_t argidx = 0;
	bool parsed;
	int32_t rc;

	memset(&cmd_arg, 0, sizeof(cmd_arg));

	PARSE_CMD_LINE_HKEY("name", cmd_arg.name, "id", cmd_arg.id);

	fprintf(stdout, "%s: key:{%s:%u}\n",
			__FUNCTION__, cmd_arg.name, cmd_arg.id);

	rc = exec_cmd(KPARSER_CMD_ADD, KPARSER_ATTR_LIST_PARSER,
			KPARSER_ATTR_LIST_PARSER_RSP,
			&cmd_arg, sizeof(cmd_arg),
			&cmd_rsp, sizeof(cmd_rsp));
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				__FUNCTION__,
				KPARSER_CMD_ADD, KPARSER_ATTR_LIST_PARSER,
				KPARSER_ATTR_LIST_PARSER_RSP, rc);
		return rc;
	}

	fprintf(stdout, "%s:cmd %d executed for attrs:{%d:%d}, op rc:[%d:%s]\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_LIST_PARSER,
			KPARSER_ATTR_LIST_PARSER_RSP,
			cmd_rsp.op_ret_code, cmd_rsp.err_str_buf);
	return 0;

einval_out:
	fprintf(stderr, "%s:cmd %d didn't execute for attrs:{%d:%d}, rc:%d\n",
			__FUNCTION__,
			KPARSER_CMD_ADD, KPARSER_ATTR_LIST_PARSER,
			KPARSER_ATTR_LIST_PARSER_RSP, rc);
	return rc;
}

int do_kparser(int argc, char **argv)
{
	if (argc < 1)
		usage();

	if (matches(*argv, "help") == 0)
		usage();

	if (genl_init_handle(&genl_rth, KPARSER_GENL_NAME, &genl_family)) {
		fprintf(stderr, "genl_init_handle() failed!\n");
		exit(-1);
	}

	if (matches(*argv, "create") == 0)
		return do_create(argc-1, (const char **) argv+1);

	if (matches(*argv, "delete") == 0)
		return do_delete(argc-1, (const char **) argv+1);

	if (matches(*argv, "list") == 0)
		return do_list(argc-1, (const char **) argv+1);

	fprintf(stderr, "Invalid key: %s. Valid command keywords are: "
			"[{create | list | delete}]\n", *argv);
	fprintf(stderr, "Try \"ip kparser help\" for more details\n");

	return -EINVAL;
}
