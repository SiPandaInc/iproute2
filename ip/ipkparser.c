/*
 * ipkparser.c	kParser CLI 
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:	Pratyush Khan <pratyush@sipanda.io>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <stdbool.h>
#include <linux/kparser.h>
#include "libgenl.h"

#include "utils.h"
#include "ip_common.h"

// WIP: TODO: use spaces while using arithmatic operators
extern const struct kparser_global_namespaces *g_namespaces[];

/* netlink socket */
static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

enum {
	op_create = 0,
	op_read,
	op_update,
	op_delete,
	op_lock,
	op_unlock,
	op_max
};

#define KPARSER_REQUEST(_req, _bufsiz, _cmd, _flags)			\
	GENL_REQUEST(_req, _bufsiz, genl_family, 0,			\
		     KPARSER_GENL_VERSION, _cmd, _flags)

#define KPARSER_NLM_MAX_LEN 8192

static void usage(FILE *stream, int argc, int *argidx, char **argv,
		bool dump_ops, bool dump_objects);

static void dump_cmd_arg(const struct kparser_global_namespaces *namespace,
		const struct kparser_conf_cmd *cmd_arg)
{
	size_t w_offset, w_len, elem_counter, elem_size, elems;
	const struct kparser_arg_key_val_token *curr_arg;
	bool array_dumped = false;
	struct kparser_hkey *hks;
	int type, i, j, k;
	const char *key;

	fprintf(stdout, "Dumping config for object/namespace:`%s`\n",
			namespace->name);
	for (i = 0; i < namespace->arg_tokens_count; i++) {
		curr_arg = &namespace->arg_tokens[i];
		key = curr_arg->key_name;
		w_offset = curr_arg->w_offset;
		w_len = curr_arg->w_len;
		elem_size = curr_arg->elem_size;
		elem_counter = curr_arg->elem_counter;
		type = curr_arg->type;

		if (curr_arg->default_template_token )
			curr_arg = curr_arg->default_template_token;

		if (type != KPARSER_ARG_VAL_ARRAY)
			type = curr_arg->type;

		if (!key)
			key = curr_arg->key_name;

		if (type == KPARSER_ARG_VAL_ARRAY)
			fprintf(stdout, "\tArray HKEYs : \n");
		else
			fprintf(stdout, "\t`%s` : ", key);

		switch (type) {
		case KPARSER_ARG_VAL_HYB_KEY_NAME:
		case KPARSER_ARG_VAL_STR:
			fprintf(stdout, "%s\n",
				(char *)(((void *) cmd_arg) + w_offset));
			break;
		case KPARSER_ARG_VAL_HYB_KEY_ID:
		case KPARSER_ARG_VAL_HYB_IDX:
			fprintf(stdout, "0x%x\n",
				*(__u16 *)(((void *) cmd_arg) + w_offset));
			break;
		case KPARSER_ARG_VAL_U8:
			fprintf(stdout, "0x%x\n",
				*(__u8 *)(((void *) cmd_arg) + w_offset));
			break;
		case KPARSER_ARG_VAL_U16:
			fprintf(stdout, "0x%x\n",
				*(__u16 *)(((void *) cmd_arg) + w_offset));
			break;
		case KPARSER_ARG_VAL_U32:
			fprintf(stdout, "0x%x\n",
				*(__u32 *)(((void *) cmd_arg) + w_offset));
			break;
		case KPARSER_ARG_VAL_U64:
			fprintf(stdout, "0x%llx\n",
				*(__u64 *)(((void *) cmd_arg) + w_offset));
			break;
		case KPARSER_ARG_VAL_SET:
			for (j = 0; j < curr_arg->value_set_len; j++) {
				if (memcmp(((void *) cmd_arg) + w_offset,
					&curr_arg->value_set[j].set_value_enum,
					w_len))
					continue;
				fprintf(stdout, "%s\n",
					curr_arg->value_set[j].set_value_str);
			}
			break;
		case KPARSER_ARG_VAL_ARRAY:
			if (array_dumped) {
				fprintf(stdout,
					"\t\tkey array already dumped\n");
				break;
			}
			if (elem_size != sizeof (*hks)) {
				fprintf(stdout,
					"array is only supported for hkeys\n");
				return;
			}
			array_dumped = true;
			elems = *(size_t *)
				(((void *) cmd_arg) + elem_counter);
			hks =  ((void *) cmd_arg) + w_offset;
			fprintf(stdout, "\t\tarray len:%lu\n", elems);
			for (k = 0; k < elems; k++) {
				fprintf(stdout, "\t\thkey[%d] : {%s:0x%x}\n",
						k, hks[k].name, hks[k].id);
			}
			break;
		default:
			printf("not supported\n");
			break;
		}
	}
}

static void dump_cmd_rsp(const struct kparser_global_namespaces *namespace,
		const void *cmd_rsp, size_t cmd_rsp_size)
{
	const struct kparser_cmd_rsp_hdr *rsp = cmd_rsp;
	int i;

	if (!cmd_rsp || cmd_rsp_size < sizeof(*rsp)) {
		fprintf(stderr, "%s: size error, %lu instead of %lu\n",
		namespace->name, cmd_rsp_size, sizeof(*rsp));
		return;
	}

	fprintf(stdout, "rsp:ret:%d, msg:%s, objs:%lu\n",
			rsp->op_ret_code, rsp->err_str_buf, rsp->objects_len);

	cmd_rsp_size -= sizeof(*rsp);

	if (rsp->op_ret_code == 0) {
		fprintf(stdout, "rsp:obj dump starts\n");
		dump_cmd_arg(namespace, &rsp->object);
		for (i = 0; i < rsp->objects_len; i++) {
			if (cmd_rsp_size < sizeof(struct kparser_conf_cmd)) {
				fprintf(stderr,
					"rsp:obj dump err, broken buffer,"
					"cmd_rsp_size:%lu expctd:%lu\n",
					cmd_rsp_size, sizeof(*rsp));
				return;
			}
			cmd_rsp_size -= sizeof(struct kparser_conf_cmd);
			dump_cmd_arg(g_namespaces[rsp->objects[i].
				     namespace_id],
				     &rsp->objects[i]);
		}
		fprintf(stdout, "rsp:obj dump ends\n");
	}
}

static inline bool parse_cmd_line_key_val_str(int argc, int *argidx,
		const char *argv[], bool mandatory, const char *key,
		void *value, size_t value_len, bool *value_err,
		bool restart)
{
	const char *str_arg_ptr;

	if (!key || !value || value_len == 0) {
		return false;
	}

	if (argc == 0 || !argv || !argidx) {
		if (mandatory)
			fprintf(stderr, "Key `%s` is missing!\n", key);
		return false;
	}

	if (*argidx > (argc - 1)) {
		if (restart)
			*argidx = 0;
		else {
			if (mandatory)
				fprintf(stderr, "Key `%s` is missing!\n", key);
			return false;
		}
	}

	if (matches(argv[*argidx], key)) {
		// start scanning from beginning
		if (restart)
			*argidx = 0;
		while (*argidx <= argc - 1) {
			if (!argv[*argidx]) {
				if (mandatory)
					fprintf(stderr,
						"Expected Key `%s` missing!\n",
						key);
				return false;
			}
			if (matches(argv[*argidx], key) == 0)
				break;
			(*argidx)++;
		}
	}

	if (*argidx > argc - 1) {
		// key not found
		if (mandatory)
			fprintf(stderr, "Expected Key `%s` notfound!\n",
					key);
		return false;
	}

	(*argidx)++;

	if (*argidx > (argc - 1) || !argv[*argidx]) {
		fprintf(stderr, "value for Key `%s` is missing!\n",
				key);
		*value_err = true;
		return false;
	}

	str_arg_ptr = argv[*argidx];
	if ((strlen(str_arg_ptr) + 1) > value_len) {
		fprintf(stderr,
			"Value `%s` of key `%s` exceeds max len %lu\n",
			str_arg_ptr, key, value_len);
		*value_err = true;
		return false;
	}
	memset(value, 0, value_len);
	(void) strncpy(value, str_arg_ptr, value_len);

	(*argidx)++;

	return true;
}

static inline bool parse_cmd_line_key_val_ints(int argc, int *argidx,
		const char *argv[], bool mandatory, const char *key,
		void *value, size_t value_len, int64_t min, int64_t max,
		bool *value_err, bool restart, bool ignore_min_max)
{
	char arg_val[KPARSER_MAX_STR_LEN_U64];
	int errno_local;
	__u64 ret_digit;
	bool rc;

	if (!key || !value || value_len == 0 ||
			value_len > sizeof(ret_digit))
		return false;

	rc = parse_cmd_line_key_val_str(argc, argidx, argv, mandatory, key,
			arg_val, sizeof(arg_val), value_err, restart);
	if (!rc || *value_err)
		return false;

	ret_digit = strtoull(arg_val, NULL, 0);
	errno_local = errno;
	if (errno_local == EINVAL || errno_local == ERANGE) {
		fprintf(stderr, "Expected digit for Key `%s`, val `%s`."
				"errno: %d in strtoull().Try again.\n",
				key, arg_val, errno_local);
		*value_err = true;
		return false;
	}

	if (!ignore_min_max && ((int64_t)ret_digit > max ||
				(int64_t)ret_digit < min)) {
		fprintf(stderr, "Value %ld for Key `%s` is out of valid "
				"range. Min: %ld, Max: %ld.\n",
				(int64_t)ret_digit, key, min, max);
		*value_err = true;
		return false;
	}

	memcpy(value, &ret_digit, value_len);

	return true;
}

static inline bool parse_element(const char *argv,
		char *ns, size_t ns_size,
		char *table_name, size_t table_name_size,
		__u16 *table_id, int *idx)
{
	char arg_u16[KPARSER_MAX_STR_LEN_U16];
	const char *tk, *tk1;
	uint64_t ret_digit;
	int32_t errno_local;

	if (!argv || !strlen(argv)) {
		return false;
	}

	// parsing pattern: "ns/ether:0x402/1"
	if (ns && ns_size) {
		tk = strchr(argv, '/');
		if ((tk - argv + 1) > ns_size) {
			fprintf(stderr, "%s:ns_size %lu less than"
					" real size %lu\n",
					__FUNCTION__, ns_size,
					tk - argv + 1);
			return false;
		}
		memcpy(ns, argv, (tk - argv + 1));
		ns[tk - argv] = '\0';
	}

	if (!table_name || !table_name_size || !table_id || !idx) {
		return true;
	}

	tk = strchr(argv, '/');
	tk++;
	tk1 = strchr(tk, ':');
	if (tk1 == NULL) {
		fprintf(stderr, "%s:Create table entry command's format is "
				"\"table/<table_name>:<table_id>/<table_idx>\"."
				"Here ':' is missing around \"%s\".\n",
				__FUNCTION__, tk);
		return false;
	}
	tk1--;
	if ((tk1 - tk) + 1 > table_name_size) {
		fprintf(stderr, "%s:Create table entry command's table"
				" key name len is %ld, but max allowed key"
				" name len is %lu\n",
				__FUNCTION__,(tk1 - tk)+1, table_name_size);
		return false;
	}
	strncpy(table_name, tk, tk1 - tk+1);
	table_name[(tk1 - tk) + 1] = '\0';
	tk1+=2;
	if (tk1 >= argv + strlen(argv)) {
		fprintf(stderr,
			"%s:Create table entry command's format is "
			"\"table/<table_name>:<table_id>/<table_idx>\"."
			"Here input required after table key name \"%s\"\n",
			__FUNCTION__, table_name);
		return false;
	}
	tk = strchr(tk1, '/');
	if (tk1 == NULL) {
		fprintf(stderr, "%s:Create table entry command's format is "
				"\"table/<table_name>:<table_id>/<table_idx>\"."
				"Here last '/' is missing around \"%s\".\n",
				__FUNCTION__, tk);
		return false;
	}
	tk--;
	if ((tk - tk1)+1 > sizeof(arg_u16)) {
		fprintf(stderr,
			"%s:Create table entry command's table"
			" key name id's length %ld, but max allowed key"
			" id len is %lu\n",
			__FUNCTION__,(tk - tk1)+1,sizeof(arg_u16));
		return false;
	}
	strncpy(arg_u16, tk1, tk - tk1+1);
	arg_u16[(tk - tk1) + 1] = '\0';
	tk+=2;
	if (tk >= argv + strlen(argv)) {
		fprintf(stderr,
			"%s:Create table entry command's format is "
			"\"table/<table_name>:<table_id>/<table_idx>\"."
			"Here input required after table key id \"%s\"\n",
			__FUNCTION__, arg_u16);
		return false;
	}
	ret_digit = strtoull(arg_u16, NULL, 0);	
	errno_local = errno;
	if (errno_local == EINVAL || errno_local == ERANGE) {
		fprintf(stderr, "Expected u16 digit for table key id,"
				"errno: %d in strtoull().Try again.\n",
				errno_local);
		return false;
	}
	if (ret_digit >= KPARSER_INVALID_ID) {
		fprintf(stderr, "Value %lu for table key id is out of valid"
				"range. Min: 0, Max: %d.Try again.\n",
				ret_digit, KPARSER_INVALID_ID);
		return false;
	}
	*table_id = (__u16)ret_digit;

	tk1 = argv + strlen(argv);
	if ((tk1 - tk)+1 > sizeof(arg_u16)) {
		fprintf(stderr,
			"%s:Create table entry command's table"
			" key index's length is %ld, but max allowed key"
			" index len is %lu\n",
			__FUNCTION__,(tk1 - tk)+1,sizeof(arg_u16));
		return false;
	}
	strncpy(arg_u16, tk, tk1 - tk+1);
	arg_u16[(tk1 - tk) + 1] = '\0';
	ret_digit = strtoull(arg_u16, NULL, 0);	
	errno_local = errno;
	if (errno_local == EINVAL || errno_local == ERANGE) {
		fprintf(stderr, "Expected u16 digit for table key idx,"
				"errno: %d in strtoull().Try again.\n",
				errno_local);
		return false;
	}
	if (ret_digit >= KPARSER_INVALID_ID) {
		fprintf(stderr, "Value %lu for table key idx is out of valid"
				"range. Min: 0, Max: %d.Try again.\n",
				ret_digit, KPARSER_INVALID_ID);
		return false;
	}
	*idx = (__u16) ret_digit;

	return true;
}

static int32_t exec_cmd(uint8_t cmd, int32_t req_attr, int32_t rsp_attr,
		const void *cmd_arg, size_t cmd_arg_size,
		void **rsp_buf, size_t *rsp_buf_size)
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
	rc = parse_rtattr(tb, KPARSER_ATTR_MAX,
			(void *) ghdr + GENL_HDRLEN, len);
	if (rc < 0) {
		fprintf(stderr, "parse_rtattr() err, rc:%d\n", rc);
		return rc;
	}

	if (tb[rsp_attr]) {
		*rsp_buf_size = RTA_PAYLOAD(tb[rsp_attr]);
		if (*rsp_buf_size) {
			*rsp_buf = calloc(1, *rsp_buf_size);
			if (!(*rsp_buf)) {
				fprintf(stderr,
					"attr:%d: calloc() failed, size:%lu\n",
					rsp_attr, *rsp_buf_size);
				*rsp_buf_size = 0;
				return -1;
			}
			memcpy(*rsp_buf, RTA_DATA(tb[rsp_attr]),
			       *rsp_buf_size);
		}
	}

	return 0;
}

static int do_cli_ns(
		const struct kparser_global_namespaces *namespace,
		int op, int argc, int *argidx, const char **argv,
		const char *hybrid_token)
{
	bool ret = true, value_err = false, ignore_min_max = false;
	const struct kparser_arg_key_val_token *curr_arg;
	size_t *dst_array_size, elem_offset, elem_size;
	struct kparser_conf_cmd *cmd_arg = NULL;
	char types_buf[KPARSER_SET_VAL_LEN_MAX];
	size_t w_offset, w_len, cmd_arg_len;
	size_t offset_adjust, elem_counter;
	const char *key, *dependent_Key;
	char tbn[KPARSER_MAX_NAME] = {};
	__u16 tbid = KPARSER_INVALID_ID;
	int i, j, rc, op_attr_id;
	void *scratch_buf = NULL;
	int other_mandatory_idx;
	size_t cmd_rsp_size = 0;
	void *cmd_rsp = NULL;
	int ns_keys_bvs[16];
	int type, elem_type;
	int tbidx = -1;

	if (hybrid_token) {
		ret = parse_element(hybrid_token, NULL, 0, tbn, sizeof(tbn),
				&tbid, &tbidx);
		if (!ret) {
			fprintf(stderr, "object `%s`: token err:%s\n",
					namespace->name, hybrid_token);
			return EINVAL;
		}
	}

	cmd_arg_len = sizeof(*cmd_arg);
	cmd_arg = calloc(1, cmd_arg_len);
	if (!cmd_arg) {
		fprintf(stderr, "object `%s`: calloc() failed\n",
				namespace->name);
		return ENOMEM;
	}

	switch (op) {
	case op_create:
		op_attr_id = namespace->create_attr_id;
		break;

	case op_update:
		op_attr_id = namespace->update_attr_id;
		break;

	case op_read:
		ignore_min_max = true;
		op_attr_id = namespace->read_attr_id;
		break;

	case op_lock:
		ignore_min_max = true;
		op_attr_id = namespace->create_attr_id;
		break;

	case op_unlock:
		ignore_min_max = true;
		op_attr_id = namespace->delete_attr_id;
		break;

	case op_delete:
		ignore_min_max = true;
		op_attr_id = namespace->delete_attr_id;
		break;

	default:
		fprintf(stderr, "invalid op:%d\n", op);
		return EINVAL;
	}

	cmd_arg->namespace_id = namespace->name_space_id;
	memset(ns_keys_bvs, 0xff, sizeof(ns_keys_bvs));

	for (i = 0; i < namespace->arg_tokens_count; i++) {
		curr_arg = &namespace->arg_tokens[i];

		key = curr_arg->key_name;
		w_offset = curr_arg->w_offset;
		w_len = curr_arg->w_len;
		elem_size = curr_arg->elem_size;
		elem_counter = curr_arg->elem_counter;
		offset_adjust = curr_arg->offset_adjust;
		type = curr_arg->type;
		elem_type = curr_arg->elem_type;

		if (curr_arg->default_template_token )
			curr_arg = curr_arg->default_template_token;

		if (type != KPARSER_ARG_VAL_ARRAY)
			type = curr_arg->type;

		if (!key)
			key = curr_arg->key_name;

		// printf("processing token key:`%s`\n", key);

		switch (type) {
		case KPARSER_ARG_VAL_HYB_KEY_NAME:
			if (!hybrid_token)
				break;
			if (strlen(tbn))
				memcpy(((void *) cmd_arg) + w_offset, tbn,
						strlen(tbn) + 1);
			else
				memcpy(((void *) cmd_arg) + w_offset,
						curr_arg->default_val,
						curr_arg->default_val_size);
			break;

		case KPARSER_ARG_VAL_HYB_KEY_ID:
			if (!hybrid_token)
				break;
			if (tbid != KPARSER_INVALID_ID)
				memcpy(((void *) cmd_arg) + w_offset, &tbid,
						w_len);
			else
				memcpy(((void *) cmd_arg) + w_offset,
						&curr_arg->def_value, w_len);
			break;

		case KPARSER_ARG_VAL_HYB_IDX:
			if (tbidx != -1)
				memcpy(((void *) cmd_arg) + w_offset,
						&tbidx, w_len);
			else
				memcpy(((void *) cmd_arg) + w_offset,
						&curr_arg->def_value, w_len);
			break;
  
		case KPARSER_ARG_VAL_STR:
			ret = parse_cmd_line_key_val_str(argc, argidx, argv,
					curr_arg->mandatory, key,
					((void *) cmd_arg) + w_offset, w_len,
					&value_err, true);
			if (ret) {
				if ((op == op_update) && curr_arg->immutable) {
					fprintf(stderr, "object `%s`: "
						"key:`%s` immutable\n",
						namespace->name, key);
					rc = EINVAL;
					goto out;
				}
				clearbit(ns_keys_bvs, i);
				break;
			}
			if (curr_arg->mandatory || value_err) {
				fprintf(stderr,
					"namespace `%s`: "
					"Failed to parse key:`%s`\n",
					namespace->name, key);
				rc = EINVAL;
				goto out;
			}
			memcpy(((void *) cmd_arg) + w_offset,
					curr_arg->default_val, w_len);
			ret = true;
			break;

		case KPARSER_ARG_VAL_U8:
		case KPARSER_ARG_VAL_U16:
		case KPARSER_ARG_VAL_U32:
		case KPARSER_ARG_VAL_U64:
			ret = parse_cmd_line_key_val_ints(argc, argidx, argv,
					curr_arg->mandatory, key,
					((void *) cmd_arg) + w_offset, w_len,
					curr_arg->min_value,
					curr_arg->max_value, &value_err,
					true, ignore_min_max);
			if (ret) {
				if ((op == op_update) && curr_arg->immutable) {
					fprintf(stderr, "object `%s`: "
						"key:`%s` immutable\n",
						namespace->name, key);
					rc = EINVAL;
					goto out;
				}
				clearbit(ns_keys_bvs, i);
				break;
			}
			if (curr_arg->mandatory || value_err) {
				fprintf(stderr,
					"namespace `%s`: "
					"Failed to parse key:`%s`\n",
					namespace->name, key);
				rc = EINVAL;
				goto out;
			}
			memcpy(((void *) cmd_arg) + w_offset,
					&curr_arg->def_value, w_len);
			ret = true;
			break;

		case KPARSER_ARG_VAL_SET:
			ret = parse_cmd_line_key_val_str(argc, argidx, argv,
					curr_arg->mandatory, key,
					types_buf, sizeof(types_buf),
					&value_err, true);
			if (!ret && (curr_arg->mandatory || value_err)) {
				fprintf(stderr,
					"namespace `%s`: "
					"Failed to parse key:%s\n",
					namespace->name, key);
				rc = EINVAL;
				goto out;
			}
			if (!ret) {
				memcpy(((void *) cmd_arg) + w_offset,
					&curr_arg->def_value_enum, w_len);
				ret = true;
				break;
			}
			if ((op == op_update) && curr_arg->immutable) {
				fprintf(stderr, "object `%s`: "
						"key:`%s` immutable\n",
						namespace->name, key);
				rc = EINVAL;
				goto out;
			}
			for (j = 0; j < curr_arg->value_set_len; j++) {
				if (matches(types_buf, 
					curr_arg->value_set[j].set_value_str)
						== 0) {
					memcpy(((void *) cmd_arg) + w_offset,
						&curr_arg->value_set[j].
							set_value_enum, w_len);
					clearbit(ns_keys_bvs, i);
					break;
				}
			}
			if (j == curr_arg->value_set_len) {
				fprintf(stderr,
					"namespace `%s`: "
					"Invalid value `%s` for key: `%s`\n",
					namespace->name, types_buf, key);
				fprintf(stderr, "\tValid set is: {");
				for (j = 0; j < curr_arg->value_set_len; j++) {
					if (j == curr_arg->value_set_len - 1)
						fprintf(stderr, "%s}\n",
							curr_arg->value_set[j].
							set_value_str);
					else
						fprintf(stderr, "%s | ",
							curr_arg->value_set[j].
							set_value_str);

				}
				rc = EINVAL;
				goto out;
			}
			break;

		case KPARSER_ARG_VAL_ARRAY:
			*argidx = 0;
			ignore_min_max = true;
array_parse_start:
			if (*argidx >= argc - 1)
				break;

			if (w_len > elem_size) {
				fprintf(stderr, "object `%s`:key:%s:"
					"config error, w_len >"
					" elem_size\n",
					namespace->name, key);
				rc = EINVAL;
				goto out;
			}

			if (offset_adjust >= elem_size) {
				fprintf(stderr, "object `%s`:key:%s:"
					"config error, offset_adjust >"
					" elem_size\n",
					namespace->name, key);
				rc = EINVAL;
				goto out;
			}

			scratch_buf = realloc(scratch_buf, elem_size);
			if (!scratch_buf) {
				fprintf(stderr, "object `%s`:key:%s:"
					"realloc() failed for scratch_buf\n",
					namespace->name, key);
				rc = ENOMEM;
				goto out;
			}
			memset(scratch_buf, 0, elem_size);

			if (elem_type == KPARSER_ARG_VAL_STR) {
				ret = parse_cmd_line_key_val_str(argc, argidx,
						argv, curr_arg->mandatory, key,
						scratch_buf + offset_adjust,
						w_len, &value_err, false);
			} else {
				ret = parse_cmd_line_key_val_ints(argc, argidx,
						argv, curr_arg->mandatory, key,
						scratch_buf + offset_adjust,
						w_len, curr_arg->min_value,
						curr_arg->max_value, &value_err,
						false, ignore_min_max);
			}

			if (!ret) {
				if (curr_arg->mandatory || value_err) {
					fprintf(stderr,
						"namespace `%s`: "
						"Failed to parse key:`%s`\n",
						namespace->name, key);
					rc = EINVAL;
					goto out;
				} else {
					ret = true;
					goto array_parse_start;
				}
			}

			if ((op == op_update) && curr_arg->immutable) {
				fprintf(stderr, "object `%s`: "
						"key:`%s` immutable\n",
						namespace->name, key);
				rc = EINVAL;
				goto out;
			}

			dst_array_size = ((void *) cmd_arg + elem_counter);
			(*dst_array_size)++;
			cmd_arg_len += *dst_array_size * elem_size;
			cmd_arg = realloc(cmd_arg, cmd_arg_len);
			if (!cmd_arg) {
				fprintf(stderr, "object `%s`:key:%s:"
					"realloc() failed\n",
					namespace->name, key);
				rc = ENOMEM;
				goto out;
			}
			elem_offset = w_offset +
				((*dst_array_size - 1) * elem_size);

			if (elem_offset + elem_size > cmd_arg_len) {
				fprintf(stderr, "object `%s`:key:%s:"
					"config error, write overflow\n",
					namespace->name, key);
				rc = EINVAL;
				goto out;
			}

			memcpy(((void *)cmd_arg) + elem_offset,
				scratch_buf, elem_size);
			ret = true;
			goto array_parse_start;

		default:
			ret = false;
			break;
		}

		if (ret == false) {
			fprintf(stderr, "object `%s`: cmdline arg error\n",
					namespace->name);
			rc = EINVAL;
			goto out;
		}
	}

	for (i = 0; i < namespace->arg_tokens_count; i++) {
		curr_arg = &namespace->arg_tokens[i];
		if (curr_arg->semi_optional == false)
			continue;
		other_mandatory_idx = curr_arg->other_mandatory_idx;
		if (other_mandatory_idx == -1)
			continue;
		key = curr_arg->key_name;
		if (curr_arg->default_template_token )
			curr_arg = curr_arg->default_template_token;
		if (!key)
			key = curr_arg->key_name;
		if ((op == op_update) && curr_arg->immutable)
			continue;
#if 0
		printf("%d:I:%d\n", i, testbit(ns_keys_bvs, i));
		printf("%d:OM:%d\n", other_mandatory_idx,
				testbit(ns_keys_bvs, other_mandatory_idx));
		printf("dependency check for token key:`%s`, %d\n",
				key, curr_arg->semi_optional);
#endif

		if (testbit(ns_keys_bvs, i) &&
				testbit(ns_keys_bvs, other_mandatory_idx)) {
			dependent_Key = namespace->arg_tokens[
				other_mandatory_idx].key_name;
			if (namespace->arg_tokens[other_mandatory_idx].
					default_template_token)
				if (!dependent_Key)
					dependent_Key = namespace->arg_tokens[
						other_mandatory_idx].
							default_template_token
							->key_name;
			fprintf(stderr, "object `%s`: either configure key"
					" `%s` and/or key `%s`\n",
					namespace->name, 
					key, dependent_Key);
			rc = EINVAL;
			goto out;
		}
	}

	dump_cmd_arg(namespace, cmd_arg);

	rc = exec_cmd(KPARSER_CMD_CONFIGURE, op_attr_id,
			namespace->rsp_attr_id,
			cmd_arg, cmd_arg_len,
			&cmd_rsp, &cmd_rsp_size);
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d"
				" attrs:{req:%d:rsp:%d}, rc:%d\n",
				namespace->name,
				KPARSER_CMD_CONFIGURE,
				op_attr_id,
				namespace->rsp_attr_id, rc);
		rc = EIO;
		goto out;
	}

	dump_cmd_rsp(namespace, cmd_rsp, cmd_rsp_size);
out:
	if (cmd_arg)
		free(cmd_arg);

	if (scratch_buf)
		free(scratch_buf);

	if (cmd_rsp)
		free(cmd_rsp);

	return rc;
}

static int do_cli(int op, int argc, int *argidx,
		const char **argv)
{
	const char *ns = NULL, *hybrid_token = NULL;
	char namespace[KPARSER_MAX_NAME];
	int i;

	if (argc && (*argidx <= (argc - 1)) && argv) {
		if (strchr(argv[*argidx], '/')) {
			hybrid_token = argv[*argidx];
			if (!parse_element(argv[*argidx],
					   namespace, sizeof(namespace),
					   NULL, 0, NULL, NULL)) {
				fprintf(stderr,
					"Invalid hybrid key format: %s\n",
					argv[*argidx]);
				fprintf(stderr, "hybrid key format is:"
					"object/<name>:<id>/<idx>\n");
				return EINVAL;;
			}
			ns = namespace;
		} else
			ns = argv[*argidx];
	}

	if (!ns)
		goto errout;

	for (i = KPARSER_NS_METADATA; i < KPARSER_NS_MAX; i++) {

		if (!g_namespaces[i])
			continue;

		if (matches(ns, g_namespaces[i]->name) == 0) {
			(*argidx)++;
			return do_cli_ns(g_namespaces[i],
					op, argc, argidx, argv,
					hybrid_token);
		}
	}

errout:
	fprintf(stderr, "Invalid namespace/object: %s\n", ns);
	usage(stderr, 0, NULL, NULL, false, true);
	return EINVAL;
}

struct kparser_cli_ops {
	int op;
	const char *op_name;
	bool hidden;
};

static struct kparser_cli_ops cli_ops[] = {
	{
		.op_name = "create",
		.op = op_create,
	},
	{
		.op_name = "read",
		.op = op_read,
	},
	{
		.op_name = "update",
		.op = op_update,
	},
	{
		.op_name = "delete",
		.op = op_delete,
	},
	{
		.op_name = "lock",
		.op = op_lock,
	},
	{
		.op_name = "unlock",
		.op = op_unlock,
	},
};

static const char *arg_val_type_str[] = 
{
	[KPARSER_ARG_VAL_STR] = "string",
	[KPARSER_ARG_VAL_U8] = "unsigned 8 bits",
	[KPARSER_ARG_VAL_U16] = "unsigned 16 bits",
	[KPARSER_ARG_VAL_U32] = "unsigned 32 bits",
	[KPARSER_ARG_VAL_U64] = "unsigned 64 bits",
	[KPARSER_ARG_VAL_BOOL] = "boolean (true/false)",
	[KPARSER_ARG_VAL_FLAG] = "flag",
	[KPARSER_ARG_VAL_SET] = "set of string constants",
	[KPARSER_ARG_VAL_ARRAY] = "array of hash keys (hkeys)",
	[KPARSER_ARG_VAL_HYB_KEY_NAME] = "hash key name in hybrind format",
	[KPARSER_ARG_VAL_HYB_KEY_ID] = "hash key ID in hybrind format",
	[KPARSER_ARG_VAL_HYB_IDX] = "table index in hybrind format",
	[KPARSER_ARG_VAL_INVALID] = "end of valid values"
};

static void usage(FILE *stream, int argc, int *argidx, char **argv,
		bool dump_ops, bool dump_objects)
{
	const struct kparser_arg_key_val_token *token;
	const char *arg_name, *ns = NULL, *arg = NULL;
	const char *default_set_value = NULL;
	int i, j, k;

	if (dump_ops)
		goto label_dump_ops;

	if (dump_objects)
		goto label_dump_objects;

	fprintf(stream,
		"Usage: ip kparser [ operations ] [ objects ] [ args ]\n");

	if (!argc || !argidx || !argv) {
		fprintf(stream, "type `help` for more details on usage\n");
		return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (matches(argv[*argidx], "operations") ==
			0)) || argc == 0) {
		if (argidx)
			(*argidx)++;
label_dump_ops:
		fprintf(stream, "operations := {");
		for (i = 0; i < sizeof(cli_ops) / sizeof(cli_ops[0]); i++) {
			if (cli_ops[i].hidden == true)
				continue;
			if (i == (sizeof(cli_ops) / sizeof(cli_ops[0]) - 1))
				fprintf(stream, "%s}\n", cli_ops[i].op_name);
			else
				fprintf(stream, "%s | ", cli_ops[i].op_name);
		}
		if (dump_ops)
			return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (matches(argv[*argidx], "objects") == 0)) ||
			argc == 0) {

		if (argidx)
			(*argidx)++;

		ns = argv[*argidx];
		if (argidx)
			(*argidx)++;
		if (ns && strcmp(ns, "args"))
			goto print_args;
		ns = NULL;

label_dump_objects:
		fprintf(stream, "objects := {");
		for (i = 0; i < KPARSER_NS_MAX; i++) {
			if (g_namespaces[i] == NULL)
				continue;
			fprintf(stream, "%s | ", g_namespaces[i]->name);
		}
		fprintf(stream, "}\n");
		if (dump_objects)
			return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (matches(argv[*argidx], "args") == 0)) ||
			argc == 0) {
		if (argidx)
			(*argidx)++;
		fprintf(stream,
			"\nAll possible args for each objects/namespaces:\n");
print_args:
		if (*argidx <= (argc - 1) && argv[*argidx]) {
			arg = argv[*argidx];
			if (matches(arg, "arg") == 0) {
				(*argidx)++;
				if (*argidx <= (argc - 1) && argv[*argidx])
					arg = argv[*argidx];
				else
					arg = NULL;
			}
		}
		for (i = 0; i < KPARSER_NS_MAX; i++) {
			if (g_namespaces[i] == NULL)
				continue;
			if (ns && strcmp(g_namespaces[i]->name, ns))
				continue;
			fprintf(stream, "%s:[", g_namespaces[i]->name);
			for (j = 0; j < g_namespaces[i]->arg_tokens_count;
					j++) {
				token = &g_namespaces[i]->arg_tokens[j];
				arg_name = token->key_name;
				if (token->default_template_token)
					token = token->default_template_token;
				if (!arg_name)
					arg_name = token->key_name;
				if (arg && matches(arg, arg_name))
					continue;
				fprintf(stream, "\n\t{");
				fprintf(stream,
					"\n\t\tname:%s, type:%s,"
					" mandatory:%d, details:%s",
					arg_name,
					arg_val_type_str[token->type],	
					token->mandatory,
					token->help_msg);
				switch(token->type) {
				case KPARSER_ARG_VAL_STR:
					fprintf(stream,
						"\n\t\tdefault:%s, maxlen:%lu",
						(const char *)
						token->default_val,
						token->str_arg_len_max);
					break;
				case KPARSER_ARG_VAL_U8:
				case KPARSER_ARG_VAL_U16:
				case KPARSER_ARG_VAL_U32:
				case KPARSER_ARG_VAL_U64:
					fprintf(stream,
						"\n\t\tmin:%llu, def:%llu,"
						" max:%llu",
						token->min_value,
						token->def_value,
						token->max_value);
					break;
				case KPARSER_ARG_VAL_SET:
					fprintf(stream, "\n\t\tset=(");
					for (k = 0; k < token->value_set_len;
							k++) {
						fprintf(stream, "`%s`",
							token->value_set[k].
							set_value_str);
						if (token->value_set[k].
							set_value_enum ==
							token->def_value_enum)
							default_set_value =
							token->value_set[k].
							set_value_str;
					}
					fprintf(stream, ")");
					fprintf(stream, "\n\t\tDefault:%s",
						default_set_value);
					break;
				case KPARSER_ARG_VAL_BOOL:
				case KPARSER_ARG_VAL_FLAG:
				case KPARSER_ARG_VAL_ARRAY:
				case KPARSER_ARG_VAL_HYB_KEY_NAME:
				case KPARSER_ARG_VAL_HYB_KEY_ID:
				case KPARSER_ARG_VAL_HYB_IDX:
				default:
					break;
				}
				fprintf(stream, "\n\t}");
				if (arg)
					break;
			}
			if (arg && j == g_namespaces[i]->arg_tokens_count)
				fprintf(stream,
					"\n\t{`%s`:invalid arg name}", arg);
			fprintf(stream, "\n]\n");
		}
	}
}

int do_kparser(int argc, char **argv)
{
	int argidx = 0;
	int i;

	if (argc < 1) {
		usage(stderr, 0, NULL, NULL, false, false);
		return EINVAL;
	}

	if (matches(*argv, "help") == 0) {
		argidx++;
		usage(stdout, argc, &argidx, argv, false, false);
		return 0;
	}

	if (genl_init_handle(&genl_rth, KPARSER_GENL_NAME, &genl_family)) {
		fprintf(stderr, "genl_init_handle() failed!\n");
		// return EIO;
	}

	for (i = 0; i < sizeof(cli_ops) / sizeof(cli_ops[0]); i++) {
		if (argc && (argidx <= (argc - 1)) && argv && argv[argidx] &&
			(matches(argv[argidx], cli_ops[i].op_name) == 0)) {
			argidx++;
			return do_cli(cli_ops[i].op, argc, &argidx,
				      (const char **) argv);
		}
	}

	fprintf(stderr, "Invalid operation: %s\n", argv[argidx]);
	usage(stderr, 0, NULL, NULL, true, false);
	fprintf(stderr, "Try \"<> kparser help\" for more details\n");
	return EINVAL;
}
