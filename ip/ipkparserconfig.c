/*
 * ipkparserconfig.c	KParser global config
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:	Pratyush Khan <pratyush@sipanda.io>
 */

#include <arpa/inet.h>
#include <linux/kparser.h>
#include "utils.h"

static const struct kparser_arg_key_val_token hkey_name = {
		.type = KPARSER_ARG_VAL_STR,
		.key_name = "name",
		.semi_optional = true,
		.other_mandatory_idx = -1,
		.immutable = true,
		.default_val_size = strlen(KPARSER_DEF_NAME_PREFIX) + 1,
		.default_val = KPARSER_DEF_NAME_PREFIX,
		.str_arg_len_max = KPARSER_MAX_NAME,
};

static const struct kparser_arg_key_val_token hkey_id = {
		.type = KPARSER_ARG_VAL_U16,
		.key_name = "id",
		.semi_optional = true,
		.other_mandatory_idx = -1,
		.immutable = true,
		.str_arg_len_max = KPARSER_MAX_U16_STR_LEN, 
		.min_value = KPARSER_USER_ID_MIN,
		.def_value = KPARSER_INVALID_ID,
		.max_value = KPARSER_USER_ID_MAX,
};

static const struct kparser_arg_set md_types[] = {
	{
		.set_value_str = "hdrdata",
		.set_value_enum = KPARSER_MD_HDRDATA,
	},
	{
		.set_value_str = "hdrlen",
		.set_value_enum = KPARSER_MD_HDRLEN,
	},
	{
		.set_value_str = "offset",
		.set_value_enum = KPARSER_MD_OFFSET,
	},
	{
		.set_value_str = "numencaps",
		.set_value_enum = KPARSER_MD_NUMENCAPS,
	},
	{
		.set_value_str = "numnodes",
		.set_value_enum = KPARSER_MD_NUMNODES,
	},
	{
		.set_value_str = "timestamp",
		.set_value_enum = KPARSER_MD_TIMESTAMP,
	},
};

static const struct kparser_arg_key_val_token md_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_config_cmd, md_conf.key.name),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_config_cmd, md_conf.key.id),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.key.id),
	},
	[2] {
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = sizeof(md_types) / sizeof(md_types[0]),
		.value_set = md_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_MD_INVALID,
		.w_offset = offsetof(struct kparser_config_cmd, md_conf.type),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.type),
	},
	[3] {
		.type = KPARSER_ARG_VAL_U16,
		.key_name = "soff",
		.str_arg_len_max = KPARSER_MAX_U16_STR_LEN,
		.min_value = 0,
		.def_value = 0,
		.max_value = 0xffff,
		.w_offset = offsetof(struct kparser_config_cmd, md_conf.soff),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.soff),
	},
	[4] {
		.type = KPARSER_ARG_VAL_U16,
		.key_name = "doff",
		.str_arg_len_max = KPARSER_MAX_U16_STR_LEN,
		.min_value = 0,
		.def_value = 0,
		.max_value = 0xffff,
		.w_offset = offsetof(struct kparser_config_cmd, md_conf.doff),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.doff),
	},
	[5] {
		.type = KPARSER_ARG_VAL_U64,
		.key_name = "len",
		.str_arg_len_max = KPARSER_MAX_U16_STR_LEN,
		.min_value = 0,
		.def_value = 2,
		.max_value = 0xffff,
		.w_offset = offsetof(struct kparser_config_cmd, md_conf.len),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.len),
	},
	[6] {
		.key_name = "array.name",
		.default_template_token = &hkey_name,
		.other_mandatory_idx = -1,
		.w_offset = offsetof(struct kparser_config_cmd,
				md_conf.array_hkey.name),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.array_hkey.name),
	},
	[7] {
		.key_name = "array.id",
		.default_template_token = &hkey_id,
		.other_mandatory_idx = -1,
		.w_offset = offsetof(struct kparser_config_cmd,
				md_conf.array_hkey.id),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.array_hkey.id),
	},
	[8] {
		.type = KPARSER_ARG_VAL_U16,
		.key_name = "array-doff",
		.str_arg_len_max = KPARSER_MAX_U16_STR_LEN,
		.min_value = 0,
		.def_value = 0,
		.max_value = 0xffff,
		.w_offset = offsetof(struct kparser_config_cmd,
				md_conf.array_doff),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.array_doff),
	},
	[9] {
		.key_name = "array-index.counter.name",
		.default_template_token = &hkey_name,
		.other_mandatory_idx = -1,
		.w_offset = offsetof(struct kparser_config_cmd,
				md_conf.array_counter_id.name),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.array_counter_id.name),
	},
	[10] {
		.key_name = "array-index.counter.id",
		.default_template_token = &hkey_id,
		.other_mandatory_idx = -1,
		.w_offset = offsetof(struct kparser_config_cmd,
				md_conf.array_counter_id.id),
		.w_len = sizeof(((struct kparser_config_cmd *) NULL)->
				md_conf.array_counter_id.id),
	},
};

static const struct kparser_global_namespaces kparser_arg_namespace_md = {
	.name_space_id = md,
	.name = "metadata",
	.arg_tokens_count = sizeof(md_key_vals) / sizeof(md_key_vals[0]),
	.arg_tokens = md_key_vals,
	.req_attr_id = KPARSER_ATTR_CREATE_MD,
	.rsp_attr_id = KPARSER_ATTR_CREATE_MD_RSP,
};

const struct kparser_global_namespaces *g_namespaces[] = {
	[md] = &kparser_arg_namespace_md,
};
