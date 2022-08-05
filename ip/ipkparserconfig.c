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
#include <stdbool.h>
#include <linux/kparser.h>
#include "utils.h"
#include "kparser_common.h"

#define KPARSER_ARG_U(bits, key, member, min, max, def, msg,		\
		json_start, json_end, ...)				\
	{								\
		.type = KPARSER_ARG_VAL_U##bits,			\
		.key_name = key,					\
		.str_arg_len_max = KPARSER_MAX_STR_LEN_U##bits,		\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
		.json_recursive_object_start_name = json_start,		\
		.json_recursive_object_start_name = json_end,		\
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_U_HEX(bits, key, member, min, max, def, msg,	\
		json_start, json_end, ...)				\
	{								\
		.type = KPARSER_ARG_VAL_U##bits,			\
		.key_name = key,					\
		.str_arg_len_max = KPARSER_MAX_STR_LEN_U##bits,		\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.print_id = KPARSER_PRINT_HEX,				\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
		.json_recursive_object_start_name = json_start,		\
		.json_recursive_object_start_name = json_end,		\
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_HKEY_NAME(key, member, msg, json_start,		\
		json_end, ...)						\
	{								\
		.key_name = key,					\
		.default_template_token = &hkey_name,			\
		.other_mandatory_idx = -1,				\
		.w_offset = offsetof(struct kparser_conf_cmd,		\
				member.name),				\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member.name),				\
		.help_msg = "object's name",				\
		.json_recursive_object_start_name = json_start,		\
		.json_recursive_object_start_name = json_end,		\
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_HKEY_ID(key, member, msg, json_start,		\
		json_end, ...)						\
	{								\
		.key_name = key,					\
		.default_template_token = &hkey_id,			\
		.other_mandatory_idx = -1,				\
		.w_offset = offsetof(struct kparser_conf_cmd,		\
				member.id),				\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member.id),				\
		.help_msg = "object's id",				\
		.json_recursive_object_start_name = json_start,		\
		.json_recursive_object_start_name = json_end,		\
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_HKEY(keyname, idname, member, msg,			\
		json_start, json_end, ...)				\
	KPARSER_ARG_HKEY_NAME(keyname, member, msg,			\
			json_start, json_end, __VA_ARGS__),		\
	KPARSER_ARG_HKEY_ID(idname, member, msg, json_start,		\
			json_end, __VA_ARGS__)

#define KPARSER_ARG_H_K_N(key, member, def, msg)			\
	{								\
		.type = KPARSER_ARG_VAL_HYB_KEY_NAME,			\
		.key_name = key,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.str_arg_len_max = KPARSER_MAX_NAME,			\
		.help_msg = msg,					\
	}

#define KPARSER_ARG_H_K_I(key, member, min, max, def, msg)		\
	{								\
		.type = KPARSER_ARG_VAL_HYB_KEY_ID,			\
		.key_name = key,					\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.print_id = KPARSER_PRINT_HEX,				\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
	}

#define KPARSER_ARG_H_K_IDX(key, member, min, max, def, msg)		\
	{								\
		.type = KPARSER_ARG_VAL_HYB_IDX,			\
		.key_name = key,					\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
	}

static const struct kparser_arg_set bool_types[] =
{
	{
		.set_value_str = "true",
		.set_value_enum = true,
	},
	{
		.set_value_str = "false",
		.set_value_enum = false,
	},
};

#define KPARSER_ARG_BOOL(key_name_arg, member, def_value, msg,		\
		json_start, json_end)					\
{									\
	.type = KPARSER_ARG_VAL_SET,					\
	.key_name = key_name_arg,					\
	.value_set_len = sizeof(bool_types) / sizeof(bool_types[0]),	\
	.value_set = bool_types,					\
	.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,			\
	.def_value_enum = def_value,					\
	.w_offset = offsetof(struct kparser_conf_cmd, member),		\
	.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->member),	\
	.help_msg = msg,						\
	.json_recursive_object_start_name = json_start,			\
	.json_recursive_object_start_name = json_end,			\
}

static const struct kparser_arg_key_val_token hkey_name = {
		.type = KPARSER_ARG_VAL_STR,
		.key_name = "name",
		.semi_optional = true,
		.other_mandatory_idx = -1,
		.str_arg_len_max = KPARSER_MAX_NAME,
		.help_msg = "strign name of hash key",
};

static const struct kparser_arg_key_val_token hkey_id = {
		.type = KPARSER_ARG_VAL_U16,
		.key_name = "id",
		.semi_optional = true,
		.other_mandatory_idx = -1,
		.str_arg_len_max = KPARSER_MAX_STR_LEN_U16,
		.min_value = KPARSER_USER_ID_MIN,
		.def_value = KPARSER_INVALID_ID,
		.max_value = KPARSER_USER_ID_MAX,
		.print_id = KPARSER_PRINT_HEX,
		.help_msg = "unsigned 16 bit hash key id",
};

static const struct kparser_arg_set expr_types[] =
{
	{
		.set_value_str = "CONDEXPR_TYPE_EQUAL",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_EQUAL,
	},
	{
		.set_value_str = "CONDEXPR_TYPE_NOTEQUAL",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_NOTEQUAL,
	},
	{
		.set_value_str = "CONDEXPR_TYPE_LT",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_LT,
	},
	{
		.set_value_str = "CONDEXPR_TYPE_LTE",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_LTE,
	},
	{
		.set_value_str = "CONDEXPR_TYPE_GT",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_GT,
	},
	{
		.set_value_str = "CONDEXPR_TYPE_GTE",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_GTE,
	},
};

static const struct kparser_arg_key_val_token cond_exprs_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_conf.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = sizeof(expr_types) / sizeof(expr_types[0]),
		.value_set = expr_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_CONDEXPR_TYPE_EQUAL,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_conf.config.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_conf.config.type),
		.json_recursive_object_start_name = "config",
		.json_recursive_object_end_name = NULL,
		.help_msg = "conditional expression type",
	},
	KPARSER_ARG_U(16, "srcoff", cond_conf.config.src_off, 0, 0xffff, 0,
			"packet data field's start offset for evaluation",
			"config", NULL),
	KPARSER_ARG_U(8, "len", cond_conf.config.length, 0, 0xff, 0,
			"packet data field length for evaluation", NULL, NULL),
	KPARSER_ARG_U_HEX(32, "mask", cond_conf.config.mask, 0,
			KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract the packet data field", NULL, NULL),
	KPARSER_ARG_U(32, "value", cond_conf.config.value, 0,
			0xffffffff, 0,
			"constant value which to be compared using the given"
			" expression and with the extracted packet data",
			NULL, "config"),
};

static const struct kparser_arg_set default_fail_types[] =
{
	{
		.set_value_str = "OKAY",
		.set_value_enum = KPARSER_OKAY,
	},
	{
		.set_value_str = "RET_OKAY",
		.set_value_enum = KPARSER_RET_OKAY,
	},
	{
		.set_value_str = "STOP_OKAY",
		.set_value_enum = KPARSER_STOP_OKAY,
	},
	{
		.set_value_str = "STOP_FAIL",
		.set_value_enum = KPARSER_STOP_FAIL,
	},
	{
		.set_value_str = "STOP_FAIL_CMP",
		.set_value_enum = KPARSER_STOP_FAIL_CMP,
	},
	{
		.set_value_str = "STOP_COMPARE",
		.set_value_enum = KPARSER_STOP_COMPARE,
	},
};

static const struct kparser_arg_set table_expr_types[] =
{
	{
		.set_value_str = "CONDEXPR_TYPE_OR",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_OR,
	},
	{
		.set_value_str = "CONDEXPR_TYPE_AND",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_AND,
	},
};

static const struct kparser_arg_key_val_token cond_exprs_table_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1,
			"hybrid table index"),
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "defaultfail",
		.value_set_len = sizeof(default_fail_types) /
			sizeof(default_fail_types[0]),
		.value_set = default_fail_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_STOP_OKAY,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.optional_value1),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.optional_value1),
		.help_msg = "kparser return code to use as default failure",
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = sizeof(table_expr_types) /
			sizeof(table_expr_types[0]),
		.value_set = table_expr_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_CONDEXPR_TYPE_OR,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.optional_value2),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.optional_value2),
		.help_msg = "conditional expression table type",
	},
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX,
			"hybrid key name for the associated conditional"
			" expression table"),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID,
			"hybrid key id for the associated conditional"
			" expression table"),
	KPARSER_ARG_HKEY("condexprs.name",
			"condexprs.id", table_conf.elem_key,
			"associated conditional expression entry's name or id",
			NULL, NULL),
};

static const struct kparser_arg_key_val_token cond_exprs_tables_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1,
			"hybrid table index"),
	KPARSER_ARG_H_K_N("condexprstable.name",
			table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX,
			"hybrid key name for the associated table of"
			" conditional expression table"),
	KPARSER_ARG_H_K_I("condexprstable.id",
			table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID,
			"hybrid key id for the associated table of"
			" conditional expression table"),
	KPARSER_ARG_HKEY("condexprs.name",
			"condexprs.id", table_conf.elem_key,
			"associated table of conditional expression's"
			" name or id",
			NULL, NULL),
};

static const struct kparser_arg_key_val_token counter_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cntr_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cntr_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cntr_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cntr_conf.key.id),
	},
	KPARSER_ARG_U(32, "max_value", cntr_conf.conf.max_value,
			0, 0xffffffff, 0, "max value of this counter",
			"config", NULL),
	KPARSER_ARG_U(32, "array_limit", cntr_conf.conf.array_limit,
			0, 0xffffffff, 0, "size of the array field in metadata",
			NULL, NULL),
	KPARSER_ARG_U(64, "array_element_size", cntr_conf.conf.el_size, 0,
			0xffffffff, 0, "metadata array field's element size",
			NULL, NULL),
	KPARSER_ARG_BOOL("reset_on_encap", cntr_conf.conf.reset_on_encap, false,
			"bool (true/false), def. false,"
			" set if counter value to"
			" be reset upon encapsulation encounter", NULL, NULL),
	KPARSER_ARG_BOOL("overwrite_last", cntr_conf.conf.overwrite_last, false,
			"bool (true/false), def. false,"
			" set if counter value to"
			" be overwritten upon max value overflow",
			NULL, NULL),
	KPARSER_ARG_BOOL("error_on_exceeded", cntr_conf.conf.error_on_exceeded,
			 false, "bool (true/false), def. false,"
			" set if want to return an error"
			" upon counter max value overflow",
			NULL, "config"),
};

static const struct kparser_arg_key_val_token counter_table_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1,
			"hybrid table index"),
	KPARSER_ARG_H_K_N("countertable.name",
			table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX,
			"hybrid key name for the associated counter table"),
	KPARSER_ARG_H_K_I("countertable.id",
			table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID,
			"hybrid key id for the associated counter table"),
	KPARSER_ARG_HKEY("counter.name", "counter.id", table_conf.elem_key,
			"associated counter table's name or id",
			NULL, NULL),
};

static const struct kparser_arg_set md_types[] = {
	{
		.set_value_str = "hdrdata",
		.set_value_enum = KPARSER_METADATA_HDRDATA,
	},
	{
		.set_value_str = "hdrlen",
		.set_value_enum = KPARSER_METADATA_HDRLEN,
	},
	{
		.set_value_str = "constant_byte",
		.set_value_enum = KPARSER_METADATA_CONSTANT_BYTE,
	},
	{
		.set_value_str = "constant_halfword",
		.set_value_enum = KPARSER_METADATA_CONSTANT_HALFWORD,
	},
	{
		.set_value_str = "offset",
		.set_value_enum = KPARSER_METADATA_OFFSET,
	},
	{
		.set_value_str = "bit_offset",
		.set_value_enum = KPARSER_METADATA_BIT_OFFSET,
	},
	{
		.set_value_str = "numencaps",
		.set_value_enum = KPARSER_METADATA_NUMENCAPS,
	},
	{
		.set_value_str = "numnodes",
		.set_value_enum = KPARSER_METADATA_NUMNODES,
	},
	{
		.set_value_str = "timestamp",
		.set_value_enum = KPARSER_METADATA_TIMESTAMP,
	},
	{
		.set_value_str = "return_code",
		.set_value_enum = KPARSER_METADATA_RETURN_CODE,
	},
	{
		.set_value_str = "counter_mode",
		.set_value_enum = KPARSER_METADATA_COUNTER,
	},
	{
		.set_value_str = "noop",
		.set_value_enum = KPARSER_METADATA_NOOP,
	},
};

static const struct kparser_arg_set counter_op_types[] = {
	{
		.set_value_str = "counter_op_noop",
		.set_value_enum = KPARSER_METADATA_COUNTEROP_NOOP,
	},
	{
		.set_value_str = "counter_op_incr",
		.set_value_enum = KPARSER_METADATA_COUNTEROP_INCR,
	},
	{
		.set_value_str = "counter_op_reset",
		.set_value_enum = KPARSER_METADATA_COUNTEROP_RST,
	},
};

static const struct kparser_arg_key_val_token md_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				md_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = sizeof(md_types) / sizeof(md_types[0]),
		.value_set = md_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_METADATA_HDRDATA,
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.type),
		.help_msg = "metadata type",
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "counterop",
		.value_set_len = sizeof(counter_op_types) /
			sizeof(counter_op_types[0]),
		.value_set = counter_op_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_METADATA_COUNTEROP_NOOP,
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.cntr_op),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.cntr_op),
		.help_msg = "associated counter operation type",
	},
	KPARSER_ARG_BOOL("isframe", md_conf.frame, false,
			"bool (true/false), def. false,"
			" set if frame of the user metadata"
			" to be used to store, else metametadata will be used"
			" to store", NULL, NULL),
	KPARSER_ARG_BOOL("isendianneeded", md_conf.e_bit, false,
			"bool (true/false), def. false,"
			" set if host byte order conversion"
			" is needed before writing to user data", NULL, NULL),
	KPARSER_ARG_U(8, "counterid", md_conf.cntr, 0, 0xff, 0,
			"associated counter id", NULL, NULL),
	KPARSER_ARG_U(8, "counterdata", md_conf.cntr_data, 0, 0xff, 0,
			"associated counter data", NULL, NULL),
	KPARSER_ARG_U(8, "constantvalue", md_conf.constant_value, 0, 0xff, 0,
			"associated constant value", NULL, NULL),
	KPARSER_ARG_U(64, "soff", md_conf.soff, 0, 0xffffffff, 0,
			"start offset", NULL, NULL),
	KPARSER_ARG_U(64, "doff", md_conf.doff, 0, 0xffffffff, 0,
			"destination metadata/metametadata offset", NULL, NULL),
	KPARSER_ARG_U(64, "length", md_conf.len, 0, 0xffffffff, 2,
			"length in bytes", NULL, NULL),
	KPARSER_ARG_U(64, "addoff", md_conf.add_off,
			KPARSER_METADATA_OFFSET_MIN,
			KPARSER_METADATA_OFFSET_MAX, 0,
			"add any additional constant offset value if needed",
			NULL, NULL, "soff"),
};

static const struct kparser_arg_key_val_token mdl_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				mdl_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				mdl_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd, mdl_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				mdl_conf.key.id),
	},
	[2] {
		.type = KPARSER_ARG_VAL_ARRAY,
		.elem_type = KPARSER_ARG_VAL_U16,
		.default_template_token = &hkey_id,
		.elem_counter = offsetof(struct kparser_conf_cmd,
				mdl_conf.metadata_keys_count),
		.elem_size = sizeof(struct kparser_hkey),
		.w_offset = offsetof(struct kparser_conf_cmd,
				mdl_conf.metadata_keys),
		.w_len = sizeof(((struct kparser_hkey *) NULL)->id),
		.key_name = "metadata.id",
		.help_msg = "associated metadata object's id",
	},
	[3] {
		.type = KPARSER_ARG_VAL_ARRAY,
		.elem_type = KPARSER_ARG_VAL_STR,
		.default_template_token = &hkey_name,
		.elem_counter = offsetof(struct kparser_conf_cmd,
				mdl_conf.metadata_keys_count),
		.elem_size = sizeof(struct kparser_hkey),
		.w_offset = offsetof(struct kparser_conf_cmd,
				mdl_conf.metadata_keys),
		.w_len = sizeof(((struct kparser_hkey *) NULL)->name),
		.key_name = "metadata.name",
		.offset_adjust = sizeof(((struct kparser_hkey *) NULL)->id),
		.help_msg = "associated metadata object's name",
	},
};

static const struct kparser_arg_set node_types[] =
{
	{
		.set_value_str = "PLAIN",
		.set_value_enum = KPARSER_NODE_TYPE_PLAIN,
	},
	{
		.set_value_str = "TLV",
		.set_value_enum = KPARSER_NODE_TYPE_TLVS,
	},
	{
		.set_value_str = "FLAGFIELDS",
		.set_value_enum = KPARSER_NODE_TYPE_FLAG_FIELDS,
	},
};

static const struct kparser_arg_set disp_limit_types[] =
{
	{
		.set_value_str = "LOOP_DISP_STOP_OKAY",
		.set_value_enum = KPARSER_LOOP_DISP_STOP_OKAY,
	},
	{
		.set_value_str = "LOOP_DISP_STOP_NODE_OKAY",
		.set_value_enum = KPARSER_LOOP_DISP_STOP_NODE_OKAY,
	},
	{
		.set_value_str = "LOOP_DISP_STOP_SUB_NODE_OKAY",
		.set_value_enum = KPARSER_LOOP_DISP_STOP_SUB_NODE_OKAY,
	},
	{
		.set_value_str = "LOOP_DISP_STOP_FAIL",
		.set_value_enum = KPARSER_LOOP_DISP_STOP_FAIL,
	},

};

#define PLAIN_NODE node_conf.plain_parse_node
#define TLVS_NODE node_conf.tlvs_parse_node
#define FLAGS_NODE node_conf.flag_fields_parse_node

static const struct kparser_arg_key_val_token parse_node_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				node_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				node_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_conf.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = sizeof(node_types) / sizeof(node_types[0]),
		.value_set = node_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_NODE_TYPE_PLAIN,
		.w_offset = offsetof(struct kparser_conf_cmd, node_conf.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_conf.type),
		.help_msg = "parse node type, default is `plain`",
	},
	KPARSER_ARG_U(32, "unknownret", PLAIN_NODE.unknown_ret,
			0, 0xffffffff, 0,
			"Code to return for a miss on the protocol table and"
			" the wildcard node is not set", NULL, NULL),
	KPARSER_ARG_HKEY("prototable.name", "prototable.id",
			PLAIN_NODE.proto_table_key,
			"associated protocol table's name or id", NULL, NULL),
	KPARSER_ARG_HKEY("wildcardparsenode.name", "wildcardparsenode.id",
			PLAIN_NODE.wildcard_parse_node_key,
			"Node use for a miss on next protocol lookup",
			NULL, NULL),
	KPARSER_ARG_HKEY("metadatatable.name", "metadatatable.id",
			PLAIN_NODE.metadata_table_key,
			"Table of parameterized metadata operations",
			NULL, NULL),

	// params for plain parse node
	KPARSER_ARG_BOOL("encap", PLAIN_NODE.proto_node.encap, false,
			"bool (true/false), def. false,"
			"Indicates an encapsulation protocol",
			"plain_proto", NULL),
	KPARSER_ARG_BOOL("overlay", PLAIN_NODE.proto_node.overlay, false,
			"bool (true/false), def. false,"
			"Indicates an overlay protocol.",
			NULL, NULL),
	KPARSER_ARG_U(64, "minlen", PLAIN_NODE.proto_node.min_len,
			0, 0xffff, 0, "Minimum length of the protocol header",
			NULL, NULL),
	// TODO
	/*
	KPARSER_ARG_BOOL("flag_fields_length",
			PLAIN_NODE.proto_node.ops.flag_fields_length, false),
	*/
	KPARSER_ARG_U(16, "hdrlenoff",
			PLAIN_NODE.proto_node.ops.pflen.src_off,
			0, 0xffff, 0,
			"relative start offset of this protocol header after"
			" the previous header ends", "hdr_length", NULL),
	KPARSER_ARG_U(8, "hdrlenlen",
			PLAIN_NODE.proto_node.ops.pflen.size,
			0, 0xff, 0, "this protocol header's length field's"
			" size in bytes", NULL, NULL),
	KPARSER_ARG_BOOL("hdrlenendian",
			PLAIN_NODE.proto_node.ops.pflen.endian, false,
			"bool (true/false), def. false,"
			" set this field if host byte order"
			" conversion is needed to calculate the header length",
			NULL, NULL),
	KPARSER_ARG_U_HEX(32, "hdrlenmask",
			PLAIN_NODE.proto_node.ops.pflen.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract the header length value", NULL, NULL),
	KPARSER_ARG_U(8, "hdrlenrightshift",
			PLAIN_NODE.proto_node.ops.pflen.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract"
			" the header length value", NULL, NULL),
	KPARSER_ARG_U(8, "hdrlenmultiplier",
			PLAIN_NODE.proto_node.ops.pflen.multiplier,
			0, 0xff, 1, "constant multiplier to calculate final"
			" header length in bytes", NULL, NULL),
	KPARSER_ARG_U(8, "hdrlenaddvalue",
			PLAIN_NODE.proto_node.ops.pflen.add_value,
			0, 0xff, 0, "constant value to be added with extracted"
			" header length to calculate final length", NULL,
			"hdr_length"),

	KPARSER_ARG_U(16, "nxtoffset",
			PLAIN_NODE.proto_node.ops.pfnext_proto.src_off,
			0, 0xffff, 0, "relative offset to identify the start"
			" of the next protocol number identifier",
			"next_proto", NULL),
	KPARSER_ARG_U_HEX(16, "nxtmask",
			PLAIN_NODE.proto_node.ops.pfnext_proto.mask,
			0, KPARSER_DEFAULT_U16_MASK, KPARSER_DEFAULT_U16_MASK,
			"mask to extract the next protocol identifier",
			NULL, NULL),
	KPARSER_ARG_U(8, "nxtlength",
			PLAIN_NODE.proto_node.ops.pfnext_proto.size,
			0, 0xff, 0,
			"size of the next protocol identifier field",
			NULL, NULL),
	KPARSER_ARG_U(8, "nxtrightshift",
			PLAIN_NODE.proto_node.ops.pfnext_proto.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract"
			" the next protocol id field", NULL, "next_proto"),

	KPARSER_ARG_HKEY("cond_exprs_table.name", "cond_exprs_table.id",
			PLAIN_NODE.proto_node.ops.cond_exprs_table,
			"table of conditional expressions table",
			NULL, NULL),

	// params for tlvs parse node
	KPARSER_ARG_U(16, "tlvhdrlenoff",
			TLVS_NODE.proto_node.ops.pfstart_offset.src_off,
			0, 0xffff, 0,
			"relative start offset of this tlv header after"
			" the previous header ends", "tlvs_hdr_len", NULL),
	KPARSER_ARG_U(8, "tlvhdrlenlen",
			TLVS_NODE.proto_node.ops.pfstart_offset.size,
			0, 0xff, 0, "this tlv header's length field's"
			" size in bytes", NULL, NULL),
	KPARSER_ARG_BOOL("tlvhdrlenendian",
			TLVS_NODE.proto_node.ops.pfstart_offset.endian, false,
			"bool (true/false), def. false,"
			" set this field if host byte order"
			" conversion is needed to calculate the header length",
			NULL, NULL),
	KPARSER_ARG_U_HEX(32, "tlvhdrlenmask",
			TLVS_NODE.proto_node.ops.pfstart_offset.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract the header length value", NULL, NULL),
	KPARSER_ARG_U(8, "tlvhdrlenrightshift",
			TLVS_NODE.proto_node.ops.pfstart_offset.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract"
			" this tlv header length value", NULL, NULL),
	KPARSER_ARG_U(8, "tlvhdrlenmultiplier",
			TLVS_NODE.proto_node.ops.pfstart_offset.multiplier,
			0, 0xff, 0, "constant multiplier to calculate final"
			" header length in bytes", NULL, NULL),
	KPARSER_ARG_U(8, "tlvhdrlenaddvalue",
			TLVS_NODE.proto_node.ops.pfstart_offset.add_value,
			0, 0xff, 0, "constant value to be added with extracted"
			" header length to calculate final length", NULL,
			"tlvs_hdr_len"),

	KPARSER_ARG_U(16, "tlvslenoff",
			TLVS_NODE.proto_node.ops.pflen.src_off,
			0, 0xffff, 0,
			"relative start offset of this tlv header's len field",
			"tlvs_len", NULL),
	KPARSER_ARG_U(8, "tlvslenlen",
			TLVS_NODE.proto_node.ops.pflen.size,
			0, 0xff, 0, "this tlv length field's size in bytes",
			NULL, NULL),
	KPARSER_ARG_BOOL("tlvslenendian",
			TLVS_NODE.proto_node.ops.pflen.endian, false,
			"bool (true/false), def. false,"
			" set this field if host byte order"
			" conversion is needed to calculate the tlv length",
			NULL, NULL),
	KPARSER_ARG_U_HEX(32, "tlvslenmask",
			TLVS_NODE.proto_node.ops.pflen.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract the tlv length value", NULL, NULL),
	KPARSER_ARG_U(8, "tlvslenrightshift",
			TLVS_NODE.proto_node.ops.pflen.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract"
			" this tlv length field's value ", NULL, NULL),
	KPARSER_ARG_U(8, "tlvslenmultiplier",
			TLVS_NODE.proto_node.ops.pflen.multiplier,
			0, 0xff, 1, "constant multiplier to calculate final"
			" tlv length in bytes", NULL, NULL),
	KPARSER_ARG_U(8, "tlvshdrlenaddvalue",
			TLVS_NODE.proto_node.ops.pflen.add_value,
			0, 0xff, 0, "constant value to be added with extracted"
			" tlv length to calculate final length ", NULL,
			"tlvs_len"),

	KPARSER_ARG_U(16, "tlvstypeoff",
			TLVS_NODE.proto_node.ops.pftype.src_off, 0, 0xffff, 0,
			"relative offset to identify the start of the next"
			" tlv type field", "tlvs_type", NULL),
	KPARSER_ARG_U_HEX(16, "tlvstypemask",
			TLVS_NODE.proto_node.ops.pftype.mask, 0,
			KPARSER_DEFAULT_U16_MASK, KPARSER_DEFAULT_U16_MASK,
			"mask to extract the next tlv type", NULL, NULL),
	KPARSER_ARG_U(8, "tlvstypelen",
			TLVS_NODE.proto_node.ops.pftype.size, 0, 0xff, 0,
			"size of the next tlv type field", NULL, NULL),
	KPARSER_ARG_U(8, "tlvstyperightshift",
			TLVS_NODE.proto_node.ops.pftype.right_shift, 0, 0xff, 0,
			"number of bits to shift right to extract the next tlv"
			" type field", NULL, "tlvs_type"),

	KPARSER_ARG_U(64, "tlvsstartoff",
			TLVS_NODE.proto_node.start_offset,
			0, 0xffffffff, 0, "When there TLVs start relative the"
			" enapsulating protocol", "config", NULL),
	KPARSER_ARG_U(8, "tlvspad1val",
			TLVS_NODE.proto_node.pad1_val,
			0, 0xff, 0, "Type value indicating one byte of TLV"
			" padding", NULL, NULL),
	KPARSER_ARG_U(8, "tlvspadnval", TLVS_NODE.proto_node.padn_val, 0, 0xff,
			0, "Type value indicating n byte of TLV", NULL, NULL),
	KPARSER_ARG_U(8, "tlvseolval", TLVS_NODE.proto_node.eol_val, 0, 0xff,
			0, "Type value that indicates end of TLV list",
			NULL, NULL),
	KPARSER_ARG_BOOL("tlvspad1enable", TLVS_NODE.proto_node.pad1_enable,
			false, "bool (true/false), def. false,"
			" Pad1 value is used to detect single byte padding",
			NULL, NULL),
	KPARSER_ARG_BOOL("tlvspadnenable", TLVS_NODE.proto_node.padn_enable,
			false, "bool (true/false), def. false,"
			" Padn value is used to detect n byte padding",
			NULL, NULL),
	KPARSER_ARG_BOOL("tlvseolenable", TLVS_NODE.proto_node.eol_enable,
			false, "bool (true/false), def. false,"
			" End of list value in eol_val is used", NULL, NULL),
	KPARSER_ARG_BOOL("tlvsfixedstartoffset",
			TLVS_NODE.proto_node.fixed_start_offset, true,
			"bool (true/false), def. true,"
			" Take start offset from start_offset", NULL, NULL),
	KPARSER_ARG_U(64, "tlvsminlen", TLVS_NODE.proto_node.min_len,
			0, 0xffffffff, 0, "Minimal length of a TLV option",
			NULL, "config"),

	KPARSER_ARG_U(32, "unknowntlvtyperet",
			TLVS_NODE.unknown_tlv_type_ret,
			0, 0xffffffff, 0, "kParser error code to return on a"
			"TLV table lookup miss and tlv_wildcard_node is NULL",
			NULL, NULL),
	KPARSER_ARG_HKEY("tlvtable.name", "tlvtable.id",
			TLVS_NODE.tlv_proto_table_key,
			"Lookup TLV table using TLV type", NULL, NULL),
	KPARSER_ARG_HKEY("tlvwildcardnode.name", "tlvwildcardnode.id",
			TLVS_NODE.tlv_wildcard_node_key, "Node to use on a TLV"
			" type lookup miss", NULL, NULL),

	KPARSER_ARG_U(16, "tlvsmaxloop", TLVS_NODE.config.max_loop,
			0, 0xffff, KPARSER_DEFAULT_TLV_MAX_LOOP,
			"Maximum number of TLVs to process",
			"tlvloopconfig", NULL),
	KPARSER_ARG_U(16, "tlvsmaxnon", TLVS_NODE.config.max_non,
			0, 0xffff, KPARSER_DEFAULT_TLV_MAX_NON_PADDING,
			"Maximum number of non-padding TLVs to process",
			NULL, NULL),
	KPARSER_ARG_U(8, "tlvsmaxplen", TLVS_NODE.config.max_plen,
			0, 0xff, KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_BYTES,
			"Maximum consecutive padding bytes", NULL, NULL),
	KPARSER_ARG_U(8, "tlvsmaxcpad", TLVS_NODE.config.max_c_pad,
			0, 0xff, KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_OPTS,
			"Maximum number of consecutive padding options",
			NULL, NULL),
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "tlvsdisplimitexceed",
		.value_set_len = sizeof(disp_limit_types) /
			sizeof(disp_limit_types[0]),
		.value_set = disp_limit_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_DEFAULT_TLV_DISP_LIMIT_EXCEED,
		.w_offset = offsetof(struct kparser_conf_cmd,
				TLVS_NODE.config.
				disp_limit_exceed),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				TLVS_NODE.config.
				disp_limit_exceed),
		.help_msg = "Disposition when a TLV parsing limit is exceeded",
	},
	KPARSER_ARG_BOOL("tlvsexceedloopcntiserr",
			TLVS_NODE.config.exceed_loop_cnt_is_err,
			KPARSER_DEFAULT_TLV_EXCEED_LOOP_CNT_ERR,
			"bool (true/false), def. false,"
			" set if exceeding maximum number of TLVS is an error",
			"flags", "tlvloopconfig"),

	// params for flag fields parse node
	KPARSER_ARG_U(16, "flagsoff",
			FLAGS_NODE.proto_node.ops.pfget_flags.src_off,
			0, 0xffff, 0, "relative starts offset of the flag in"
			" the current protocol header",
			"flagsget", NULL),
	KPARSER_ARG_U_HEX(32, "flagsmask",
			FLAGS_NODE.proto_node.ops.pfget_flags.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract flag from the given offset",
			NULL, NULL),
	KPARSER_ARG_U(8, "flagslen",
			FLAGS_NODE.proto_node.ops.pfget_flags.size,
			0, 0xff, 0, "length of the flag", NULL, "flagsget"),

	KPARSER_ARG_U(16, "flagsstartoff",
			FLAGS_NODE.proto_node.ops.
			pfstart_fields_offset.src_off,
			0, 0xffff, 0, "relative offset in the current protocol"
			" header where flag field starts", "flagsstart", NULL),
	KPARSER_ARG_U(8, "flagsofflen",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.size,
			0, 0xff, 0, "<TODO>", NULL, NULL),
	KPARSER_ARG_BOOL("flagsoffendian",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.endian,
			false,
			"bool (true/false), def. false,"
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U_HEX(32, "flagsoffmask",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(8, "flagsoffrightshift",
			FLAGS_NODE.proto_node.ops.
			pfstart_fields_offset.right_shift,
			0, 0xff, 0, "<TODO>", NULL, NULL),
	KPARSER_ARG_U(8, "flagsoffmultiplier",
			FLAGS_NODE.proto_node.ops.
			pfstart_fields_offset.multiplier,
			0, 0xff, 0, "<TODO>", NULL, NULL),
	KPARSER_ARG_U(8, "flagsoffaddvalue",
			FLAGS_NODE.proto_node.ops.
			pfstart_fields_offset.add_value,
			0, 0xff, 0, "<TODO>", NULL, "flagsstart"),

	KPARSER_ARG_HKEY("flagfieldstable.name", "flagfieldstable.id",
			FLAGS_NODE.proto_node.flag_fields_table_hkey,
			"table of flag fields", NULL, NULL),
	KPARSER_ARG_HKEY("flagfieldsprototable.name",
			"flagfieldsprototable.id",
			FLAGS_NODE.flag_fields_proto_table_key,
			"flag fields protocol table", NULL, "flags"),
};

static const struct kparser_arg_key_val_token proto_table_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1, "<TODO>"),
	KPARSER_ARG_U(32, "value", table_conf.optional_value1,
			0, 0xffffffff, 0,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX, "<TODO>"),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID, "<TODO>"),
	KPARSER_ARG_HKEY("node.name", "node.id", table_conf.elem_key,
			NULL, NULL,
			"<TODO>", NULL, NULL),
};

static const struct kparser_arg_key_val_token tlv_parse_node_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_node_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_node_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_node_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_node_conf.key.id),
	},
	KPARSER_ARG_U(64, "minlen", tlv_node_conf.node_proto.min_len,
			0, 0xffffffff, 0,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(64, "maxlen", tlv_node_conf.node_proto.max_len, 0,
			0xffffffff, 0xffffffff, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_BOOL("is_padding", tlv_node_conf.node_proto.is_padding, 
			false,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(16, "pfoverlay_type_src_off",
			tlv_node_conf.node_proto.ops.pfoverlay_type.src_off,
			0, 0xffff, 0, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U_HEX(16, "pfoverlay_type_mask",
			tlv_node_conf.node_proto.ops.pfoverlay_type.mask,
			0, KPARSER_DEFAULT_U16_MASK, KPARSER_DEFAULT_U16_MASK,
			
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(8, "pfoverlay_type_size",
			tlv_node_conf.node_proto.ops.pfoverlay_type.size,
			0, 0xff, 0,
			
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(8, "pfoverlay_type_right_shift",
			tlv_node_conf.node_proto.ops.
			pfoverlay_type.right_shift,
			0, 0xff, 0, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("cond_exprs_table.name", "cond_exprs_table.id",
			tlv_node_conf.node_proto.ops.cond_exprs_table,
			"<TODO>", NULL, NULL),

	KPARSER_ARG_U(32, "unknown_ret", tlv_node_conf.unknown_ret,
			0, 0xffffffff, 0, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("overlay_proto_tlvs_table_key.name",
			"overlay_proto_tlvs_table_key.id",
			tlv_node_conf.overlay_proto_tlvs_table_key,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("overlay_wildcard_parse_node.name",
			"overlay_wildcard_parse_node.id",
			tlv_node_conf.overlay_wildcard_parse_node_key,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("metadatatable.name", "metadatatable.id",
			tlv_node_conf.metadata_table_key,
			"<TODO>", NULL, NULL),
};

static const struct kparser_arg_key_val_token tlv_proto_table_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1, "<TODO>"),
	KPARSER_ARG_U(32, "tlvtype", table_conf.optional_value1,
			0, 0xffffffff, 0, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX, "<TODO>"),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID, "<TODO>"),
	KPARSER_ARG_HKEY("tlvnode.name", "tlvnode.id", table_conf.elem_key,
			"<TODO>", NULL, NULL),
};

static const struct kparser_arg_key_val_token flag_field_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				flag_field_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				flag_field_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				flag_field_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				flag_field_conf.key.id),
	},

	KPARSER_ARG_U(32, "flag", flag_field_conf.conf.flag,
			0, 0xffffffff, 0, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U_HEX(32, "mask", flag_field_conf.conf.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(64, "size", flag_field_conf.conf.size, 0,
			0xffffffff, 0, 
			"<TODO>", NULL, NULL),
};

static const struct kparser_arg_key_val_token flag_field_table_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1, "<TODO>"),
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX, "<TODO>"),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID, "<TODO>"),
	KPARSER_ARG_HKEY("flag_field.name", "flag_field.id",
			table_conf.elem_key,
			"<TODO>", NULL, NULL),
};

static const struct kparser_arg_key_val_token
flag_field_node_parse_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				flag_field_node_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				flag_field_node_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				flag_field_node_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				flag_field_node_conf.key.id),
	},

	KPARSER_ARG_HKEY("metadata_table.name", "metadata_table.id",
			flag_field_node_conf.metadata_table_key,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("cond_exprs_table.name", "cond_exprs_table.id",
			flag_field_node_conf.ops.cond_exprs_table_key,
			"<TODO>", NULL, NULL),
};

static const struct kparser_arg_key_val_token
flag_field_proto_table_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1, "<TODO>"),
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX, "<TODO>"),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID, "<TODO>"),
	KPARSER_ARG_HKEY("flag_field_parse_node.name",
			"flag_field_parse_node.id",
			table_conf.elem_key,
			"<TODO>", NULL, NULL),
};

static const struct kparser_arg_key_val_token parser_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				parser_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				parser_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				parser_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				parser_conf.key.id),
	},
	KPARSER_ARG_U(16, "flags", parser_conf.config.flags, 0, 0xffff,
			0, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(16, "maxnodes", parser_conf.config.max_nodes,
			0, 0xffff, KPARSER_MAX_NODES, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(16, "maxencaps", parser_conf.config.max_encaps,
			0, 0xffff, KPARSER_MAX_ENCAPS, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(16, "maxframes", parser_conf.config.max_frames,
			0, 0xffff, KPARSER_MAX_FRAMES, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(64, "metametasize", parser_conf.config.metameta_size, 0,
			0xffffffff, 0, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_U(64, "framesize", parser_conf.config.frame_size, 0,
			0xffffffff, 0, 
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("rootnode.name", "rootnode.id",
			parser_conf.root_node_key,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("oknode.name", "oknode.id",
			parser_conf.ok_node_key,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("failnode.name", "failnode.id",
			parser_conf.fail_node_key,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("atencapnode.name", "atencapnode.id",
			parser_conf.atencap_node_key,
			"<TODO>", NULL, NULL),
	KPARSER_ARG_HKEY("cntrstable.name", "cntrstable.id",
			parser_conf.cntrs_table_key,
			"<TODO>", NULL, NULL),
};

static const struct kparser_arg_key_val_token parser_lock_unlock_key_vals[] =
{
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				obj_key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				obj_key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				obj_key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				obj_key.id),
	},
};

#define DEFINE_NAMESPACE_MEMBERS(id, namestr, token_name, desc)		\
	.name_space_id = id,						\
	.name = namestr,						\
	.alias = #id,							\
	.arg_tokens_count = sizeof(token_name) / sizeof(token_name[0]),	\
	.arg_tokens = token_name,					\
	.create_attr_id = KPARSER_ATTR_CREATE_##id,			\
	.update_attr_id = KPARSER_ATTR_UPDATE_##id,			\
	.read_attr_id = KPARSER_ATTR_READ_##id,				\
	.delete_attr_id = KPARSER_ATTR_DELETE_##id,			\
	.rsp_attr_id = KPARSER_ATTR_RSP_##id,				\
	.description = desc

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS,
			"cond_exprs",
			cond_exprs_vals,
			"conditional expressions object"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs_table =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS_TABLE,
			"cond_exprs_list",
			cond_exprs_table_key_vals,
			"conditional expressions table object"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs_tables =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS_TABLES,
			"cond_exprs_table",
			cond_exprs_tables_key_vals,
			"table of conditional expressions table object"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_counter =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_COUNTER,
			"counter",
			counter_key_vals,
			"counter object"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_counter_table =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_COUNTER_TABLE,
			"countertable",
			counter_table_key_vals,
			"table of counter object"),
};

static const struct kparser_global_namespaces kparser_arg_namespace_metadata =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_METADATA, "metadata", md_key_vals,
			"metadata object"),
};

static const struct kparser_global_namespaces kparser_arg_namespace_metalist =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_METALIST,
			"metalist", mdl_key_vals,
			"list of metadata object"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_parse_node =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_NODE_PARSE, "node",
			parse_node_key_vals,
			"plain parse node object"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_proto_table =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_PROTO_TABLE, "table",
			proto_table_key_vals,
			"table of parse node objects"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_parse_node =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_TLV_NODE_PARSE, "tlvnode",
			tlv_parse_node_key_vals,
			"tlv (type-length-value) parse node objects"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_proto_table =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_TLV_PROTO_TABLE, "tlvtable",
			tlv_proto_table_key_vals,
			"table of tlv parse node objects"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD, "flag_field",
			flag_field_key_vals,
			"flag field object"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_table =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_TABLE,
			"flag_field_table",
			flag_field_table_key_vals,
			"table of flag field object"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_node_parse =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_NODE_PARSE,
			"flag_field_parse_node",
			flag_field_node_parse_key_vals,
			"flag-field parse node objects"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_proto_table =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
			"flag_field_proto_table",
			flag_field_proto_table_key_vals,
			"table of flag-field parse node objects"),
};

static const struct kparser_global_namespaces kparser_arg_namespace_parser =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_PARSER, "parser", parser_key_vals,
			"parser objects"),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_parser_lock_unlock =
{
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_OP_PARSER_LOCK_UNLOCK,
			"parser_lock_unlock", parser_lock_unlock_key_vals,
			"lock/unlock a parser object using key"),
};

const struct kparser_global_namespaces *g_namespaces[] =
{
	[KPARSER_NS_INVALID] = NULL,

	[KPARSER_NS_CONDEXPRS] = &kparser_arg_namespace_cond_exprs,
	[KPARSER_NS_CONDEXPRS_TABLE] =
		&kparser_arg_namespace_cond_exprs_table,
	[KPARSER_NS_CONDEXPRS_TABLES] =
		&kparser_arg_namespace_cond_exprs_tables,

	[KPARSER_NS_COUNTER] = &kparser_arg_namespace_counter,
	[KPARSER_NS_COUNTER_TABLE] = &kparser_arg_namespace_counter_table,

	[KPARSER_NS_METADATA] = &kparser_arg_namespace_metadata,
	[KPARSER_NS_METALIST] = &kparser_arg_namespace_metalist,

	[KPARSER_NS_NODE_PARSE] = &kparser_arg_namespace_parse_node,
	[KPARSER_NS_PROTO_TABLE] = &kparser_arg_namespace_proto_table,

	[KPARSER_NS_TLV_NODE_PARSE] = &kparser_arg_namespace_tlv_parse_node,
	[KPARSER_NS_TLV_PROTO_TABLE] = &kparser_arg_namespace_tlv_proto_table,

	[KPARSER_NS_FLAG_FIELD] = &kparser_arg_namespace_flag_field, 
	[KPARSER_NS_FLAG_FIELD_TABLE] =
		&kparser_arg_namespace_flag_field_table,
	[KPARSER_NS_FLAG_FIELD_NODE_PARSE] =
		&kparser_arg_namespace_flag_field_node_parse,
	[KPARSER_NS_FLAG_FIELD_PROTO_TABLE] =
		&kparser_arg_namespace_flag_field_proto_table,

	[KPARSER_NS_PARSER] = &kparser_arg_namespace_parser,

	[KPARSER_NS_OP_PARSER_LOCK_UNLOCK] =
		&kparser_arg_namespace_parser_lock_unlock,

	[KPARSER_NS_MAX] = NULL,
};
