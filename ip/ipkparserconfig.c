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

#define KPARSER_ARG_U(bits, key, member, min, max, def, msg, ...)	\
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
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_U_HEX(bits, key, member, min, max, def, msg, ...)	\
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
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_HKEY_NAME(key, member)				\
	{								\
		.key_name = key,					\
		.default_template_token = &hkey_name,			\
		.other_mandatory_idx = -1,				\
		.w_offset = offsetof(struct kparser_conf_cmd,		\
				member.name),				\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member.name),				\
	}

#define KPARSER_ARG_HKEY_ID(key, member)				\
	{								\
		.key_name = key,					\
		.default_template_token = &hkey_id,			\
		.other_mandatory_idx = -1,				\
		.w_offset = offsetof(struct kparser_conf_cmd,		\
				member.id),				\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member.id),				\
	}

#define KPARSER_ARG_HKEY(keyname, idname, member)			\
	KPARSER_ARG_HKEY_NAME(keyname, member),				\
	KPARSER_ARG_HKEY_ID(idname, member)

#define KPARSER_ARG_H_K_N(key, member, def)				\
	{								\
		.type = KPARSER_ARG_VAL_HYB_KEY_NAME,			\
		.key_name = key,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.str_arg_len_max = KPARSER_MAX_NAME,			\
		.help_msg = "<type hybrid key name>",			\
	}

#define KPARSER_ARG_H_K_I(key, member, min, max, def)			\
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
		.help_msg = "<type hybrid key id>",			\
	}

#define KPARSER_ARG_H_K_IDX(key, member, min, max, def)			\
	{								\
		.type = KPARSER_ARG_VAL_HYB_IDX,			\
		.key_name = key,					\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = "<type hybrid idx>",			\
	}

static const struct kparser_arg_set bool_types[] = {
	{
		.set_value_str = "true",
		.set_value_enum = true,
	},
	{
		.set_value_str = "false",
		.set_value_enum = false,
	},
};

#define KPARSER_ARG_BOOL(key_name_arg, member, def_value)		\
{									\
	.type = KPARSER_ARG_VAL_SET,					\
	.key_name = key_name_arg,					\
	.value_set_len = sizeof(bool_types) / sizeof(bool_types[0]),	\
	.value_set = bool_types,					\
	.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,			\
	.def_value_enum = def_value,					\
	.w_offset = offsetof(struct kparser_conf_cmd, member),		\
	.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->member),	\
	.help_msg = "<type str bool set (true/false), def. false>",	\
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
		.help_msg = "16 bit hash key id",
};

static const struct kparser_arg_set expr_types[] = {
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

static const struct kparser_arg_key_val_token cond_exprs_vals[] = {
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
		.help_msg = "<type str set>",
	},
	KPARSER_ARG_U(16, "soff", cond_conf.config.src_off, 0, 0xffff, 0,
			"start offset"),
	KPARSER_ARG_U(8, "len", cond_conf.config.length, 0, 0xff, 0,
			"length"),
	KPARSER_ARG_U_HEX(32, "mask", cond_conf.config.mask, 0,
			KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"length"),
	KPARSER_ARG_U(32, "value", cond_conf.config.value, 0,
			0xffffffff, 0, "length"),
};

static const struct kparser_arg_set default_fail_types[] = {
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

static const struct kparser_arg_set table_expr_types[] = {
	{
		.set_value_str = "CONDEXPR_TYPE_OR",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_OR,
	},
	{
		.set_value_str = "CONDEXPR_TYPE_AND",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_AND,
	},
};

static const struct kparser_arg_key_val_token cond_exprs_table_key_vals[] = {
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
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1),
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "default_fail",
		.value_set_len = sizeof(default_fail_types) /
			sizeof(default_fail_types[0]),
		.value_set = default_fail_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_STOP_OKAY,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.optional_value1),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.optional_value1),
		.help_msg = "<relevant kparser return codes>",
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
		.help_msg = "<type str set>",
	},
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY("condexprs.name",
			"condexprs.id", table_conf.elem_key),
};

static const struct kparser_arg_key_val_token cond_exprs_tables_key_vals[] = {
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
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1),
	KPARSER_ARG_H_K_N("condexprstable.name",
			table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("condexprstable.id",
			table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY("condexprs.name",
			"condexprs.id", table_conf.elem_key),
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
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(32, "array_limit", cntr_conf.conf.array_limit,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(64, "el_size", cntr_conf.conf.el_size, 0,
			0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("reset_on_encap", cntr_conf.conf.reset_on_encap,
			 false),
	KPARSER_ARG_BOOL("overwrite_last", cntr_conf.conf.overwrite_last,
			 false),
	KPARSER_ARG_BOOL("error_on_exceeded", cntr_conf.conf.error_on_exceeded,
			 false),
};

static const struct kparser_arg_key_val_token counter_table_key_vals[] = {
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
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1),
	KPARSER_ARG_H_K_N("counter_table.name",
			table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("counter_table.id",
			table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY("counter.name",
			"counter.id", table_conf.elem_key),
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

static const struct kparser_arg_key_val_token md_key_vals[] = {
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
		.help_msg = "<type str set>",
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "counter_op",
		.value_set_len = sizeof(counter_op_types) /
			sizeof(counter_op_types[0]),
		.value_set = counter_op_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_METADATA_COUNTEROP_NOOP,
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.cntr_op),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.cntr_op),
		.help_msg = "<type str set>",
	},
	KPARSER_ARG_BOOL("is_frame", md_conf.frame, false),
	KPARSER_ARG_BOOL("is_endian_needed", md_conf.e_bit, false),
	// KPARSER_ARG_BOOL("is_bit_offset", md_conf.bit_offset, false),
	KPARSER_ARG_BOOL("set_high_bit", md_conf.set_high_bit, false),
	KPARSER_ARG_U(8, "counter_id", md_conf.cntr, 0, 0xff, 0,
			"<dummy msg>"),
	KPARSER_ARG_U(8, "counter_data", md_conf.cntr_data, 0, 0xff, 0,
			"<dummy msg>"),
	KPARSER_ARG_U(8, "constant_value", md_conf.constant_value, 0, 0xff, 0,
			"<dummy msg>"),
	KPARSER_ARG_U(64, "soff", md_conf.soff, 0, 0xffffffff, 0,
			"start offset"),
	KPARSER_ARG_U(64, "doff", md_conf.doff, 0, 0xffffffff, 0,
			"destination offset"),
	KPARSER_ARG_U(64, "len", md_conf.len, 0, 0xffffffff, 2, "length"),
	KPARSER_ARG_U(64, "add_off", md_conf.add_off,
			KPARSER_METADATA_OFFSET_MIN,
			KPARSER_METADATA_OFFSET_MAX,
			KPARSER_METADATA_OFFSET_INVALID,
			"add_offset"),
	KPARSER_ARG_U_HEX(64, "add_bit_off", md_conf.add_bit_off,
			KPARSER_METADATA_OFFSET_MIN,
			KPARSER_METADATA_OFFSET_MAX,
			KPARSER_METADATA_OFFSET_INVALID,
			"add_bit_offset", "add_off", "soff"),
};

static const struct kparser_arg_key_val_token mdl_key_vals[] = {
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
	},
};

static const struct kparser_arg_set node_types[] = {
	{
		.set_value_str = "plain",
		.set_value_enum = KPARSER_NODE_TYPE_PLAIN,
	},
	{
		.set_value_str = "tlvs",
		.set_value_enum = KPARSER_NODE_TYPE_TLVS,
	},
	{
		.set_value_str = "flag_fields",
		.set_value_enum = KPARSER_NODE_TYPE_FLAG_FIELDS,
	},
};

static const struct kparser_arg_set disp_limit_types[] = {
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

static const struct kparser_arg_key_val_token parse_node_key_vals[] = {
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
		.help_msg = "<type  str set, def. plain>",
	},
	KPARSER_ARG_U(32, "unknown_ret", PLAIN_NODE.unknown_ret,
			0, 0xffffffff, 0, "dummy_help"),

	KPARSER_ARG_HKEY("proto_table.name", "proto_table.id",
			PLAIN_NODE.proto_table_key),

	KPARSER_ARG_HKEY("wildcard_parse_node.name", "wildcard_parse_node.id",
			PLAIN_NODE.wildcard_parse_node_key),

	KPARSER_ARG_HKEY("metadata_table.name", "metadata_table.id",
			PLAIN_NODE.metadata_table_key),

	// params for plain parse node
	KPARSER_ARG_BOOL("encap", PLAIN_NODE.proto_node.encap, false),
	KPARSER_ARG_BOOL("overlay", PLAIN_NODE.proto_node.overlay, false),
	KPARSER_ARG_U(64, "min_len", PLAIN_NODE.proto_node.min_len,
			0, 0xffff, 0, "min len"),
	KPARSER_ARG_BOOL("flag_fields_length",
			PLAIN_NODE.proto_node.ops.flag_fields_length, false),
	KPARSER_ARG_BOOL("len_parameterized",
			PLAIN_NODE.proto_node.ops.len_parameterized, false),
	KPARSER_ARG_U(16, "pflen_src_off",
			PLAIN_NODE.proto_node.ops.pflen.src_off,
			0, 0xffff, 0, "src offset"),
	KPARSER_ARG_U(8, "pflen_size",
			PLAIN_NODE.proto_node.ops.pflen.size,
			0, 0xff, 0, "size"),
	KPARSER_ARG_BOOL("pflen_endian",
			PLAIN_NODE.proto_node.ops.pflen.endian, false),
	KPARSER_ARG_U_HEX(32, "pflen_mask",
			PLAIN_NODE.proto_node.ops.pflen.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"dummy_help"),
	KPARSER_ARG_U(8, "pflen_right_shift",
			PLAIN_NODE.proto_node.ops.pflen.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pflen_multiplier",
			PLAIN_NODE.proto_node.ops.pflen.multiplier,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pflen_add_value",
			PLAIN_NODE.proto_node.ops.pflen.add_value,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(16, "pfnext_src_off",
			PLAIN_NODE.proto_node.ops.pfnext_proto.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U_HEX(16, "pfnext_mask",
			PLAIN_NODE.proto_node.ops.pfnext_proto.mask,
			0, KPARSER_DEFAULT_U16_MASK, KPARSER_DEFAULT_U16_MASK,
			"dummy_help"),
	KPARSER_ARG_U(8, "pfnext_size",
			PLAIN_NODE.proto_node.ops.pfnext_proto.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pfnext_rightshift",
			PLAIN_NODE.proto_node.ops.pfnext_proto.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("cond_exprs_parameterized",
			PLAIN_NODE.proto_node.ops.cond_exprs_parameterized,
			false),
	KPARSER_ARG_HKEY("cond_exprs_table.name", "cond_exprs_table.id",
			PLAIN_NODE.proto_node.ops.cond_exprs_table),

	// params for tlvs parse node
	KPARSER_ARG_U(16, "tlvs_off_src_off",
			TLVS_NODE.proto_node.
			ops.pfstart_offset.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_off_size",
			TLVS_NODE.proto_node.
			ops.pfstart_offset.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("tlvs_ops_off_endian",
			TLVS_NODE.proto_node.
			ops.pfstart_offset.endian, false),
	KPARSER_ARG_U_HEX(32, "tlvs_ops_off_mask",
			TLVS_NODE.proto_node.
			ops.pfstart_offset.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"dummy_help"),
	KPARSER_ARG_U(8, "tlvs_ops_off_right_shift",
			TLVS_NODE.proto_node.
			ops.pfstart_offset.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_ops_off_multiplier",
			TLVS_NODE.proto_node.
			ops.pfstart_offset.multiplier,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_ops_off_add_value",
			TLVS_NODE.proto_node.
			ops.pfstart_offset.add_value,
			0, 0xff, 0, "dummy_help"),

	KPARSER_ARG_BOOL("tlvs_len_parameterized",
			TLVS_NODE.proto_node.
			ops.len_parameterized, false),
	KPARSER_ARG_U(16, "tlvs_len_src_off",
			TLVS_NODE.proto_node.
			ops.pflen.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_len_size",
			TLVS_NODE.proto_node.
			ops.pflen.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("tlvs_ops_len_endian",
			TLVS_NODE.proto_node.
			ops.pflen.endian, false),
	KPARSER_ARG_U_HEX(32, "tlvs_ops_len_mask",
			TLVS_NODE.proto_node.
			ops.pflen.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"dummy_help"),
	KPARSER_ARG_U(8, "tlvs_ops_len_right_shift",
			TLVS_NODE.proto_node.
			ops.pflen.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_ops_len_multiplier",
			TLVS_NODE.proto_node.
			ops.pflen.multiplier,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_ops_len_add_value",
			TLVS_NODE.proto_node.
			ops.pflen.add_value,
			0, 0xff, 0, "dummy_help"),

	KPARSER_ARG_BOOL("tlvs_type_parameterized",
			TLVS_NODE.proto_node.
			ops.type_parameterized, false),
	KPARSER_ARG_U(16, "tlvs_type_src_off",
			TLVS_NODE.proto_node.
			ops.pftype.src_off, 0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U_HEX(16, "tlvs_type_mask",
			TLVS_NODE.proto_node.
			ops.pftype.mask, 0, KPARSER_DEFAULT_U16_MASK,
			KPARSER_DEFAULT_U16_MASK, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_type_size",
			TLVS_NODE.proto_node.
			ops.pftype.size, 0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_type_rightshift",
			TLVS_NODE.proto_node.
			ops.pftype.right_shift, 0, 0xff, 0, "dummy_help"),

	KPARSER_ARG_U(64, "tlvs_start_offset",
			TLVS_NODE.proto_node.start_offset,
			0, 0xffffffffffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_pad1_val",
			TLVS_NODE.proto_node.pad1_val,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_padn_val", TLVS_NODE.
			proto_node.padn_val, 0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "tlvs_eol_val", TLVS_NODE.
			proto_node.eol_val, 0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("tlvs_pad1_enable", TLVS_NODE.
			proto_node.pad1_enable, false),
	KPARSER_ARG_BOOL("tlvs_padn_enable", TLVS_NODE.
			proto_node.padn_enable, false),
	KPARSER_ARG_BOOL("tlvs_eol_enable", TLVS_NODE.
			proto_node.eol_enable, false),
	KPARSER_ARG_BOOL("tlvs_fixed_start_offset",
			TLVS_NODE.proto_node.fixed_start_offset, false),
	KPARSER_ARG_U(64, "tlvs_min_len", TLVS_NODE.proto_node.min_len,
			0, 0xffffffffffffffff, 0, "dummy_help"),

	KPARSER_ARG_U(32, "unknown_tlv_type_ret",
			TLVS_NODE.unknown_tlv_type_ret,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_HKEY("tlv_proto_table.name", "tlv_proto_table.id",
			TLVS_NODE.tlv_proto_table_key),
	KPARSER_ARG_HKEY("tlv_wildcard_node.name", "tlv_wildcard_node.id",
			TLVS_NODE.tlv_wildcard_node_key),


	KPARSER_ARG_U(16, "tlvs_max_loop", TLVS_NODE.config.max_loop,
			0, 0xffff, KPARSER_DEFAULT_TLV_MAX_LOOP,
			"dummy_help"),
	KPARSER_ARG_U(16, "tlvs_max_non", TLVS_NODE.config.max_non,
			0, 0xffff, KPARSER_DEFAULT_TLV_MAX_NON_PADDING,
			"dummy_help"),
	KPARSER_ARG_U(8, "tlvs_max_plen", TLVS_NODE.config.max_plen,
			0, 0xff, KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_BYTES,
			"dummy_help"),
	KPARSER_ARG_U(8, "tlvs_max_c_pad", TLVS_NODE.config.max_c_pad,
			0, 0xff, KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_OPTS,
			"dummy_help"),
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "tlvs_disp_limit_exceed",
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
		.help_msg = "<type  str set, def. plain>",
	},
	KPARSER_ARG_BOOL("tlvs_exceed_loop_cnt_is_err",
			TLVS_NODE.config.exceed_loop_cnt_is_err,
			KPARSER_DEFAULT_TLV_EXCEED_LOOP_CNT_ERR),

	// params for flag fields parse node
	KPARSER_ARG_BOOL("flags_get_parameterized",
			FLAGS_NODE.proto_node.ops.get_flags_parameterized,
			false),
	KPARSER_ARG_U(16, "flags_get_src_off",
			FLAGS_NODE.proto_node.ops.pfget_flags.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U_HEX(32, "flags_get_mask",
			FLAGS_NODE.proto_node.ops.pfget_flags.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"dummy_help"),
	KPARSER_ARG_U(8, "flags_get_size",
			FLAGS_NODE.proto_node.ops.pfget_flags.size,
			0, 0xff, 0, "dummy_help"),

	KPARSER_ARG_BOOL("flags_soff_parameterized",
			FLAGS_NODE.proto_node.ops.
			start_fields_offset_parameterized, false),
	KPARSER_ARG_U(16, "flags_soff_src_off",
			FLAGS_NODE.proto_node.ops.
			pfstart_fields_offset.src_off,
			0, 0xffff, 0, "src offset"),
	KPARSER_ARG_U(8, "flags_soff_size",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.size,
			0, 0xff, 0, "size"),
	KPARSER_ARG_BOOL("flags_soff_endian",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.endian,
			false),
	KPARSER_ARG_U_HEX(32, "flags_soff_mask",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"dummy_help"),
	KPARSER_ARG_U(8, "flags_soff_right_shift",
			FLAGS_NODE.proto_node.ops.
			pfstart_fields_offset.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "flags_soff_multiplier",
			FLAGS_NODE.proto_node.ops.
			pfstart_fields_offset.multiplier,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "flags_soff_add_value",
			FLAGS_NODE.proto_node.ops.
			pfstart_fields_offset.add_value,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_HKEY("flag_fields_table.name", "flag_fields_table.id",
			FLAGS_NODE.proto_node.flag_fields_table_hkey),
	KPARSER_ARG_HKEY("flag_fields_proto_table.name",
			"flag_fields_proto_table.id",
			FLAGS_NODE.flag_fields_proto_table_key),
};

static const struct kparser_arg_key_val_token proto_table_key_vals[] = {
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
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1),
	KPARSER_ARG_U(32, "value", table_conf.optional_value1,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY("node.name", "node.id", table_conf.elem_key),
};

static const struct kparser_arg_key_val_token tlv_parse_node_key_vals[] = {
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
	KPARSER_ARG_U(64, "min_len", tlv_node_conf.node_proto.min_len,
			0, 0xffffffffffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(64, "max_len", tlv_node_conf.node_proto.max_len, 0,
			0xffffffffffffffff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("is_padding", tlv_node_conf.node_proto.is_padding, 
			false),
	KPARSER_ARG_U(16, "pfoverlay_type_src_off",
			tlv_node_conf.node_proto.ops.pfoverlay_type.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U_HEX(16, "pfoverlay_type_mask",
			tlv_node_conf.node_proto.ops.pfoverlay_type.mask,
			0, KPARSER_DEFAULT_U16_MASK, KPARSER_DEFAULT_U16_MASK,
			"dummy_help"),
	KPARSER_ARG_U(8, "pfoverlay_type_size",
			tlv_node_conf.node_proto.ops.pfoverlay_type.size,
			0, 0xff, 0,
			"dummy_help"),
	KPARSER_ARG_U(8, "pfoverlay_type_right_shift",
			tlv_node_conf.node_proto.ops.
			pfoverlay_type.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_HKEY("cond_exprs_table.name", "cond_exprs_table.id",
			tlv_node_conf.node_proto.ops.cond_exprs_table),

	KPARSER_ARG_U(32, "unknown_ret", tlv_node_conf.unknown_ret,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_HKEY("overlay_proto_tlvs_table_key.name",
			"overlay_proto_tlvs_table_key.id",
			tlv_node_conf.overlay_proto_tlvs_table_key),
	KPARSER_ARG_HKEY("overlay_wildcard_parse_node.name",
			"overlay_wildcard_parse_node.id",
			tlv_node_conf.overlay_wildcard_parse_node_key),
	KPARSER_ARG_HKEY("metadata_table.name", "metadata_table.id",
			tlv_node_conf.metadata_table_key),
};

static const struct kparser_arg_key_val_token tlv_proto_table_key_vals[] = {
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
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1),
	KPARSER_ARG_U(32, "type", table_conf.optional_value1,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY("tlv_parse_node.name",
			"tlv_parse_node.id", table_conf.elem_key),
};

static const struct kparser_arg_key_val_token flag_field_key_vals[] = {
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
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_U_HEX(32, "mask", flag_field_conf.conf.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"dummy_help"),
	KPARSER_ARG_U(64, "size", flag_field_conf.conf.size, 0,
			0xffffffff, 0, "dummy_help"),
};

static const struct kparser_arg_key_val_token flag_field_table_key_vals[] = {
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
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1),
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY("flag_field.name", "flag_field.id",
			table_conf.elem_key),
};

static const struct kparser_arg_key_val_token
flag_field_node_parse_key_vals[] = {
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
			flag_field_node_conf.metadata_table_key),
	KPARSER_ARG_HKEY("cond_exprs_table.name", "cond_exprs_table.id",
			flag_field_node_conf.ops.cond_exprs_table_key),
};

static const struct kparser_arg_key_val_token
flag_field_proto_table_key_vals[] = {
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
	KPARSER_ARG_H_K_IDX("idx", table_conf.idx, 0, -1, -1),
	KPARSER_ARG_H_K_N("table.name", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("table.id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY("flag_field_parse_node.name",
			"flag_field_parse_node.id",
			table_conf.elem_key),
};

static const struct kparser_arg_key_val_token parser_key_vals[] = {
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
		      0, "dummy_help"),
	KPARSER_ARG_U(16, "max_nodes", parser_conf.config.max_nodes,
		      0, 0xffff, KPARSER_MAX_NODES, "dummy_help"),
	KPARSER_ARG_U(16, "max_encaps", parser_conf.config.max_encaps,
		      0, 0xffff, KPARSER_MAX_ENCAPS, "dummy_help"),
	KPARSER_ARG_U(16, "max_frames", parser_conf.config.max_frames,
		      0, 0xffff, KPARSER_MAX_FRAMES, "dummy_help"),
	KPARSER_ARG_U(64, "metameta_size", parser_conf.config.metameta_size, 0,
		      0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(64, "frame_size", parser_conf.config.frame_size, 0,
		      0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_HKEY("root_node.name", "root_node.id",
			 parser_conf.root_node_key),
	KPARSER_ARG_HKEY("ok_node.name", "ok_node.id",
			 parser_conf.ok_node_key),
	KPARSER_ARG_HKEY("fail_node.name", "fail_node.id",
			 parser_conf.fail_node_key),
	KPARSER_ARG_HKEY("atencap_node.name", "atencap_node.id",
			 parser_conf.atencap_node_key),
	KPARSER_ARG_HKEY("cntrs_table.name", "cntrs_table.id",
			 parser_conf.cntrs_table_key),
};

static const struct kparser_arg_key_val_token parser_lock_unlock_key_vals[] = {
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

#define DEFINE_NAMESPACE_MEMBERS(id, namestr, token_name)		\
	.name_space_id = id,						\
	.name = namestr,						\
	.alias = #id,							\
	.arg_tokens_count = sizeof(token_name) / sizeof(token_name[0]),	\
	.arg_tokens = token_name,					\
	.create_attr_id = KPARSER_ATTR_CREATE_##id,			\
	.update_attr_id = KPARSER_ATTR_UPDATE_##id,			\
	.read_attr_id = KPARSER_ATTR_READ_##id,				\
	.delete_attr_id = KPARSER_ATTR_DELETE_##id,			\
	.rsp_attr_id = KPARSER_ATTR_RSP_##id

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS,
				 "cond_exprs",
				 cond_exprs_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS_TABLE,
				 "cond_exprs_table",
				 cond_exprs_table_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs_tables = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS_TABLES,
				 "cond_exprs_tables",
				 cond_exprs_tables_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_counter = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_COUNTER,
				 "counter",
				 counter_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_counter_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_COUNTER_TABLE,
				 "counter_table",
				 counter_table_key_vals),
};

static const struct kparser_global_namespaces kparser_arg_namespace_md = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_METADATA, "metadata", md_key_vals),
};

static const struct kparser_global_namespaces kparser_arg_namespace_ml = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_METALIST,
				 "metalist", mdl_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_parse_node = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_NODE_PARSE, "parse_node",
				 parse_node_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_proto_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_PROTO_TABLE, "proto_table",
				 proto_table_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_parse_node = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_TLV_NODE_PARSE, "tlv_parse_node",
				 tlv_parse_node_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_proto_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_TLV_PROTO_TABLE, "tlv_proto_table",
				 tlv_proto_table_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD, "flag_field",
				 flag_field_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_TABLE,
				 "flag_field_table",
				 flag_field_table_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_node_parse = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_NODE_PARSE,
				 "flag_field_parse_node",
				 flag_field_node_parse_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_proto_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
				 "flag_field_proto_table",
				 flag_field_proto_table_key_vals),
};

static const struct kparser_global_namespaces kparser_arg_namespace_parser = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_PARSER, "parser", parser_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_parser_lock_unlock = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_OP_PARSER_LOCK_UNLOCK,
			"parser_lock_unlock", parser_lock_unlock_key_vals),
};

const struct kparser_global_namespaces *g_namespaces[] = {
	[KPARSER_NS_INVALID] = NULL,

	[KPARSER_NS_CONDEXPRS] = &kparser_arg_namespace_cond_exprs,
	[KPARSER_NS_CONDEXPRS_TABLE] =
		&kparser_arg_namespace_cond_exprs_table,
	[KPARSER_NS_CONDEXPRS_TABLES] =
		&kparser_arg_namespace_cond_exprs_tables,

	[KPARSER_NS_COUNTER] = &kparser_arg_namespace_counter,
	[KPARSER_NS_COUNTER_TABLE] = &kparser_arg_namespace_counter_table,

	[KPARSER_NS_METADATA] = &kparser_arg_namespace_md,
	[KPARSER_NS_METALIST] = &kparser_arg_namespace_ml,

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
