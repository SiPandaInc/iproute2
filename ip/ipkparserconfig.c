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

#define KPARSER_ARG_U(bits, key, member, min, max, def, msg)		\
	{								\
		.type = KPARSER_ARG_VAL_U##bits,			\
		.key_name = key,					\
		.str_arg_len_max = KPARSER_MAX_STR_LEN_U##bits,		\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
	}								\

#define KPARSER_ARG_HKEY_NAME(key, member)				\
	{								\
		.key_name = key,					\
		.default_template_token = &hkey_name,			\
		.other_mandatory_idx = -1,				\
		.w_offset = offsetof(struct kparser_conf_cmd,		\
				member.name),				\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member.name),				\
	}								\

#define KPARSER_ARG_HKEY_ID(key, member)				\
	{								\
		.key_name = key,					\
		.default_template_token = &hkey_id,			\
		.other_mandatory_idx = -1,				\
		.w_offset = offsetof(struct kparser_conf_cmd,		\
				member.id),				\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member.id),				\
	}								\

#define KPARSER_ARG_H_K_N(key, member, def)				\
	{								\
		.type = KPARSER_ARG_VAL_HYB_KEY_NAME,			\
		.key_name = key,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.default_val_size = strlen(def) + 1,			\
		.default_val = def,					\
		.str_arg_len_max = KPARSER_MAX_NAME,			\
		.help_msg = "<type hybrid key name>",			\
	}								\

#define KPARSER_ARG_H_K_I(key, member, min, max, def)			\
	{								\
		.type = KPARSER_ARG_VAL_HYB_KEY_ID,			\
		.key_name = key,					\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = "<type hybrid key id>",			\
	}								\

#define KPARSER_ARG_H_K_IDX(key, member, min, max, def)			\
	{								\
		.type = KPARSER_ARG_VAL_HYB_IDX,			\
		.key_name = key,					\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = "<type hybrid idx>",			\
	}								\

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

#define KPARSER_ARG_BOOL(key_name_arg, member)						\
	{										\
		.type = KPARSER_ARG_VAL_SET,						\
		.key_name = key_name_arg,						\
		.value_set_len = sizeof(bool_types) / sizeof(bool_types[0]),		\
		.value_set = bool_types,						\
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,				\
		.def_value_enum = false,						\
		.w_offset = offsetof(struct kparser_conf_cmd, member),			\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->member),		\
		.help_msg = "<type str bool set (true/false), def. false>",		\
	}										\

static const struct kparser_arg_key_val_token hkey_name = {
		.type = KPARSER_ARG_VAL_STR,
		.key_name = "name",
		.semi_optional = true,
		.other_mandatory_idx = -1,
		.default_val_size = strlen(KPARSER_DEF_NAME_PREFIX) + 1,
		.default_val = KPARSER_DEF_NAME_PREFIX,
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
		.help_msg = "16 bit hash key id",
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
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.key.name),
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
		.def_value_enum = KPARSER_MD_HDRDATA,
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.type),
		.help_msg = "<type str set>",
	},
	KPARSER_ARG_U(16, "soff", md_conf.soff, 0, 0xffff, 0, "start offset"),
	KPARSER_ARG_U(16, "doff", md_conf.doff, 0, 0xffff, 0,
			"destination offset"),
	KPARSER_ARG_U(64, "len", md_conf.len, 0, 0xffff, 2, "length"),
	KPARSER_ARG_BOOL("is_frame", md_conf.frame),
	KPARSER_ARG_BOOL("is_endian_needed", md_conf.e_bit),
	KPARSER_ARG_HKEY_NAME("array.name", md_conf.array_hkey),
	KPARSER_ARG_HKEY_ID("array.id", md_conf.array_hkey),
	KPARSER_ARG_U(16, "array-doff", md_conf.array_doff, 0, 0xffff, 0,
			"array destination offset"),
	KPARSER_ARG_HKEY_NAME("array-index.counter.name", md_conf.array_counter_id),
	KPARSER_ARG_HKEY_ID("array-index.counter.id", md_conf.array_counter_id),
};

static const struct kparser_arg_key_val_token mdl_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd, mdl_conf.key.name),
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

static const struct kparser_arg_key_val_token proto_node_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd, node_proto_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_proto_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd, node_proto_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_proto_conf.key.id),
	},
	KPARSER_ARG_BOOL("encap", node_proto_conf.encap),
	KPARSER_ARG_BOOL("overlay", node_proto_conf.overlay),
	KPARSER_ARG_U(64, "min_len", node_proto_conf.min_len, 0, 0xffff, 0,
			"min len"),
	KPARSER_ARG_BOOL("flag_fields_length",
			node_proto_conf.ops.flag_fields_length),
	KPARSER_ARG_BOOL("len_parameterized",
			node_proto_conf.ops.len_parameterized),
	KPARSER_ARG_U(16, "pflen_src_off", node_proto_conf.ops.pflen.src_off,
			0, 0xffff, 0, "src offset"),
	KPARSER_ARG_U(8, "pflen_size", node_proto_conf.ops.pflen.size, 0, 0xff, 0,
			"size"),
	KPARSER_ARG_BOOL("pflen_endian", node_proto_conf.ops.pflen.endian),
	KPARSER_ARG_U(32, "pflen_mask", node_proto_conf.ops.pflen.mask,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pflen_right_shift",
			node_proto_conf.ops.pflen.right_shift, 0, 0xff, 0, 
			"dummy_help"),
	KPARSER_ARG_U(8, "pflen_multiplier",
			node_proto_conf.ops.pflen.multiplier, 0, 0xff, 0,
			"dummy_help"),
	KPARSER_ARG_U(8, "pflen_add_value",
			node_proto_conf.ops.pflen.add_value, 0, 0xff, 0,
			"dummy_help"),
	KPARSER_ARG_BOOL("next_proto_parameterized",
			node_proto_conf.ops.next_proto_parameterized),
	KPARSER_ARG_U(16, "pfnext_src_off",
			node_proto_conf.ops.pfnext_proto.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(16, "pfnext_mask",
			node_proto_conf.ops.pfnext_proto.mask,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pfnext_size",
			node_proto_conf.ops.pfnext_proto.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pfnext_rightshift",
			node_proto_conf.ops.pfnext_proto.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("cond_exprs_parameterized",
			node_proto_conf.ops.cond_exprs_parameterized),
	KPARSER_ARG_HKEY_NAME("cond_exprs_table.name",
			node_proto_conf.ops.cond_exprs_table),
	KPARSER_ARG_HKEY_ID("cond_exprs_table.id",
			node_proto_conf.ops.cond_exprs_table),
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

static const struct kparser_arg_key_val_token parse_node_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd, node_parse_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_parse_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd, node_parse_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_parse_conf.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = sizeof(node_types) / sizeof(node_types[0]),
		.value_set = node_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_NODE_TYPE_PLAIN,
		.w_offset = offsetof(struct kparser_conf_cmd, node_parse_conf.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_parse_conf.type),
		.help_msg = "<type  str set, def. plain>",
	},
	KPARSER_ARG_U(32, "unknown_ret", node_parse_conf.unknown_ret,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_HKEY_NAME("proto_node.name", node_parse_conf.proto_node),
	KPARSER_ARG_HKEY_ID("proto_node.id", node_parse_conf.proto_node),
	KPARSER_ARG_HKEY_NAME("proto_table.name", node_parse_conf.proto_table),
	KPARSER_ARG_HKEY_ID("proto_table.id", node_parse_conf.proto_table),
	KPARSER_ARG_HKEY_NAME("wildcard_parse_node.name",
			node_parse_conf.wildcard_parse_node),
	KPARSER_ARG_HKEY_ID("wildcard_parse_node.id",
			node_parse_conf.wildcard_parse_node),
	KPARSER_ARG_HKEY_NAME("metadata_table.name",
			node_parse_conf.metadata_table),
	KPARSER_ARG_HKEY_ID("metadata_table.id",
			node_parse_conf.metadata_table),
};

static const struct kparser_arg_key_val_token proto_table_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				proto_table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				proto_table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				proto_table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				proto_table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", proto_table_conf.idx, 0, -1, -1),
	KPARSER_ARG_U(32, "value", proto_table_conf.value, 0, 0xffffffff, 0,
			"dummy_help"),
	KPARSER_ARG_H_K_N("table.name", proto_table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("table.id", proto_table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY_NAME("node.name", proto_table_conf.parse_node_key),
	KPARSER_ARG_HKEY_ID("node.id", proto_table_conf.parse_node_key),
};

static const struct kparser_arg_key_val_token tlv_proto_node_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_node_proto_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_node_proto_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_node_proto_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_node_proto_conf.key.id),
	},
	KPARSER_ARG_U(64, "min_len", tlv_node_proto_conf.min_len,
			0, 0xffffffffffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(64, "max_len", tlv_node_proto_conf.max_len, 0,
			0xffffffffffffffff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("is_padding", tlv_node_proto_conf.is_padding),
	KPARSER_ARG_U(16, "pfoverlay_type_src_off",
			tlv_node_proto_conf.ops.pfoverlay_type.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(16, "pfoverlay_type_mask",
			tlv_node_proto_conf.ops.pfoverlay_type.mask,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pfoverlay_type_size",
			tlv_node_proto_conf.ops.pfoverlay_type.size, 0, 0xff, 0,
			"dummy_help"),
	KPARSER_ARG_U(8, "pfoverlay_type_right_shift",
			tlv_node_proto_conf.ops.pfoverlay_type.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_HKEY_NAME("cond_exprs_table.name",
			tlv_node_proto_conf.ops.cond_exprs_table),
	KPARSER_ARG_HKEY_ID("cond_exprs_table.id",
			tlv_node_proto_conf.ops.cond_exprs_table),
};

static const struct kparser_arg_key_val_token tlv_parse_node_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_node_parse_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_node_parse_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_node_parse_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_node_parse_conf.key.id),
	},
	KPARSER_ARG_U(32, "unknown_ret", tlv_node_parse_conf.unknown_ret,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_HKEY_NAME("proto_tlv_node_key.name",
			tlv_node_parse_conf.proto_tlv_node_key),
	KPARSER_ARG_HKEY_ID("proto_tlv_node_key.id",
			tlv_node_parse_conf.proto_tlv_node_key),
	KPARSER_ARG_HKEY_NAME("overlay_proto_tlvs_table_key.name",
			tlv_node_parse_conf.overlay_proto_tlvs_table_key),
	KPARSER_ARG_HKEY_ID("overlay_proto_tlvs_table_key.id",
			tlv_node_parse_conf.overlay_proto_tlvs_table_key),
	KPARSER_ARG_HKEY_NAME("overlay_wildcard_parse_node.name",
			tlv_node_parse_conf.overlay_wildcard_parse_node),
	KPARSER_ARG_HKEY_ID("overlay_wildcard_parse_node.id",
			tlv_node_parse_conf.overlay_wildcard_parse_node),
	KPARSER_ARG_HKEY_NAME("metadata_table.name",
			tlv_node_parse_conf.metadata_table),
	KPARSER_ARG_HKEY_ID("metadata_table.id",
			tlv_node_parse_conf.metadata_table),
};

static const struct kparser_arg_key_val_token tlvs_proto_node_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlvs_node_proto_conf.proto_node.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlvs_node_proto_conf.proto_node.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlvs_node_proto_conf.proto_node.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlvs_node_proto_conf.proto_node.key.id),
	},
	KPARSER_ARG_BOOL("encap", tlvs_node_proto_conf.proto_node.encap),
	KPARSER_ARG_BOOL("overlay", tlvs_node_proto_conf.proto_node.overlay),
	KPARSER_ARG_U(64, "min_len", tlvs_node_proto_conf.proto_node.min_len,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(16, "pflen_src_off",
			tlvs_node_proto_conf.proto_node.ops.pflen.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pflen_size", tlvs_node_proto_conf.proto_node.ops.pflen.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("pflen_endian",
			tlvs_node_proto_conf.proto_node.ops.pflen.endian),
	KPARSER_ARG_U(32, "pflen_mask", tlvs_node_proto_conf.proto_node.ops.pflen.mask,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pflen_right_shift",
			tlvs_node_proto_conf.proto_node.ops.pflen.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pflen_multiplier",
			tlvs_node_proto_conf.proto_node.ops.pflen.multiplier,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pflen_add_value",
			tlvs_node_proto_conf.proto_node.ops.pflen.add_value,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(16, "pfnext_src_off",
			tlvs_node_proto_conf.proto_node.ops.pfnext_proto.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(16, "pfnext_mask",
			tlvs_node_proto_conf.proto_node.ops.pfnext_proto.mask,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pfnext_size",
			tlvs_node_proto_conf.proto_node.ops.pfnext_proto.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pfnext_rightshift",
			tlvs_node_proto_conf.proto_node.ops.pfnext_proto.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_HKEY_NAME("cond_exprs_table.name",
			tlvs_node_proto_conf.proto_node.ops.cond_exprs_table),
	KPARSER_ARG_HKEY_ID("cond_exprs_table.id",
			tlvs_node_proto_conf.proto_node.ops.cond_exprs_table),
	KPARSER_ARG_U(16, "ops_off_src_off",
			tlvs_node_proto_conf.ops.pfstart_offset.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "ops_off_size",
			tlvs_node_proto_conf.ops.pfstart_offset.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("ops_off_endian", tlvs_node_proto_conf.ops.pfstart_offset.endian),
	KPARSER_ARG_U(32, "ops_off_mask",
			tlvs_node_proto_conf.ops.pfstart_offset.mask,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "ops_off_right_shift",
			tlvs_node_proto_conf.ops.pfstart_offset.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "ops_off_multiplier",
			tlvs_node_proto_conf.ops.pfstart_offset.multiplier,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "ops_off_add_value",
			tlvs_node_proto_conf.ops.pfstart_offset.add_value,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("len_parameterized",
			tlvs_node_proto_conf.ops.len_parameterized),
	KPARSER_ARG_U(16, "ops_len_src_off",
			tlvs_node_proto_conf.ops.pflen.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "ops_len_size",
			tlvs_node_proto_conf.ops.pflen.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("ops_len_endian",
			tlvs_node_proto_conf.ops.pflen.endian),
	KPARSER_ARG_U(32, "ops_len_mask",
			tlvs_node_proto_conf.ops.pflen.mask,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "ops_len_right_shift",
			tlvs_node_proto_conf.ops.pflen.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "ops_len_multiplier",
			tlvs_node_proto_conf.ops.pflen.multiplier,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "ops_len_add_value",
			tlvs_node_proto_conf.ops.pflen.add_value,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("type_parameterized",
			tlvs_node_proto_conf.ops.type_parameterized),
	KPARSER_ARG_U(16, "type_src_off",
			tlvs_node_proto_conf.ops.pftype.src_off,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(16, "type_mask",
			tlvs_node_proto_conf.ops.pftype.mask,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "type_size",
			tlvs_node_proto_conf.ops.pftype.size,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "type_rightshift",
			tlvs_node_proto_conf.ops.pftype.right_shift,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "pad1_val", tlvs_node_proto_conf.pad1_val, 0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "padn_val", tlvs_node_proto_conf.padn_val, 0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "eol_val", tlvs_node_proto_conf.eol_val, 0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_BOOL("pad1_enable", tlvs_node_proto_conf.pad1_enable),
	KPARSER_ARG_BOOL("padn_enable", tlvs_node_proto_conf.padn_enable),
	KPARSER_ARG_BOOL("eol_enable", tlvs_node_proto_conf.eol_enable),
	KPARSER_ARG_BOOL("fixed_start_offset", tlvs_node_proto_conf.fixed_start_offset),
	KPARSER_ARG_U(64, "min_len", tlvs_node_proto_conf.min_len,
			0, 0xffffffffffffffff, 0, "dummy_help"),
};

static const struct kparser_arg_key_val_token tlvs_parse_node_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlvs_node_parse_conf.parse_node.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlvs_node_parse_conf.parse_node.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlvs_node_parse_conf.parse_node.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlvs_node_parse_conf.parse_node.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = sizeof(node_types) / sizeof(node_types[0]),
		.value_set = node_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_NODE_TYPE_PLAIN,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlvs_node_parse_conf.parse_node.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlvs_node_parse_conf.parse_node.type),
		.help_msg = "<type  str set, def. plain>",
	},
	KPARSER_ARG_U(32, "unknown_ret",
			tlvs_node_parse_conf.parse_node.unknown_ret,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_HKEY_NAME("proto_node.name",
			tlvs_node_parse_conf.parse_node.proto_node),
	KPARSER_ARG_HKEY_ID("proto_node.id",
			tlvs_node_parse_conf.parse_node.proto_node),
	KPARSER_ARG_HKEY_NAME("proto_table.name",
			tlvs_node_parse_conf.parse_node.proto_table),
	KPARSER_ARG_HKEY_ID("proto_table.id",
			tlvs_node_parse_conf.parse_node.proto_table),
	KPARSER_ARG_HKEY_NAME("wildcard_parse_node.name",
			tlvs_node_parse_conf.parse_node.wildcard_parse_node),
	KPARSER_ARG_HKEY_ID("wildcard_parse_node.id",
			tlvs_node_parse_conf.parse_node.wildcard_parse_node),
	KPARSER_ARG_HKEY_NAME("metadata_table.name",
			tlvs_node_parse_conf.parse_node.metadata_table),
	KPARSER_ARG_HKEY_ID("metadata_table.id",
			tlvs_node_parse_conf.parse_node.metadata_table),
	KPARSER_ARG_HKEY_NAME("tlv_proto_table_key.name",
			tlvs_node_parse_conf.tlv_proto_table_key),
	KPARSER_ARG_HKEY_ID("tlv_proto_table_key.id",
			tlvs_node_parse_conf.tlv_proto_table_key),
	KPARSER_ARG_U(32, "unknown_ret",
			tlvs_node_parse_conf.unknown_ret,
			0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_HKEY_NAME("tlv_wildcard_parse_node.name",
			tlvs_node_parse_conf.tlv_wildcard_parse_node),
	KPARSER_ARG_HKEY_ID("tlv_wildcard_parse_node.id",
			tlvs_node_parse_conf.tlv_wildcard_parse_node),
	KPARSER_ARG_U(16, "max_loop", tlvs_node_parse_conf.config.max_loop,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(16, "max_non", tlvs_node_parse_conf.config.max_non,
			0, 0xffff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "max_plen", tlvs_node_parse_conf.config.max_plen,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "max_c_pad", tlvs_node_parse_conf.config.max_c_pad,
			0, 0xff, 0, "dummy_help"),
	KPARSER_ARG_U(8, "disp_limit_exceed",
			tlvs_node_parse_conf.config.disp_limit_exceed,
			0, 3, 0, "dummy_help"),
	KPARSER_ARG_BOOL("exceed_loop_cnt_is_err",
			tlvs_node_parse_conf.config.exceed_loop_cnt_is_err),
};

static const struct kparser_arg_key_val_token tlv_proto_table_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_proto_table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_proto_table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_proto_table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_proto_table_conf.key.id),
	},
	KPARSER_ARG_U(32, "type", tlv_proto_table_conf.type, 0, 0xffffffff, 0, "dummy_help"),
	KPARSER_ARG_H_K_IDX("idx", tlv_proto_table_conf.idx, 0, -1, -1),
	KPARSER_ARG_H_K_N("table.name", tlv_proto_table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("table.id", tlv_proto_table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
	KPARSER_ARG_HKEY_NAME("parse_tlv_node_key.name",
			tlv_proto_table_conf.parse_tlv_node_key),
	KPARSER_ARG_HKEY_ID("parse_tlv_node_key.id",
			tlv_proto_table_conf.parse_tlv_node_key),
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
	KPARSER_ARG_HKEY_NAME("root_node_key.name", parser_conf.root_node_key),
	KPARSER_ARG_HKEY_ID("root_node_key.id", parser_conf.root_node_key),
	KPARSER_ARG_HKEY_NAME("ok_node_key.name", parser_conf.ok_node_key),
	KPARSER_ARG_HKEY_ID("ok_node_key.id", parser_conf.ok_node_key),
	KPARSER_ARG_HKEY_NAME("fail_node_key.name", parser_conf.fail_node_key),
	KPARSER_ARG_HKEY_ID("fail_node_key.id", parser_conf.fail_node_key),
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
		.w_offset = offsetof(struct kparser_conf_cmd, cond_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd, cond_conf.key.id),
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
	KPARSER_ARG_U(32, "mask", cond_conf.config.mask, 0,
			0xffffffff, 0, "length"),
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
				cond_table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_table_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", cond_table_conf.idx, 0, -1, -1),
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "default_fail",
		.value_set_len = sizeof(default_fail_types) /
			sizeof(default_fail_types[0]),
		.value_set = default_fail_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_STOP_OKAY,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_table_conf.default_fail),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_table_conf.default_fail),
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
				cond_table_conf.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_table_conf.type),
		.help_msg = "<type str set>",
	},
	KPARSER_ARG_H_K_N("condexprs.name", cond_table_conf.condexpr_expr_key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("condexprs.id", cond_table_conf.condexpr_expr_key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
};

static const struct kparser_arg_key_val_token cond_exprs_tables_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_tables_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_tables_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_tables_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_tables_conf.key.id),
	},
	KPARSER_ARG_H_K_IDX("idx", cond_tables_conf.idx, 0, -1, -1),
	KPARSER_ARG_H_K_N("condexprstable.name",
			cond_tables_conf.condexpr_expr_table_key.name,
			KPARSER_DEF_NAME_PREFIX),
	KPARSER_ARG_H_K_I("condexprstable.id",
			cond_tables_conf.condexpr_expr_table_key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID),
};

#define DEFINE_NAMESPACE_MEMBERS(id, token_name)			\
	.name_space_id = KPARSER_NS_##id,				\
	.name = KPARSER_NAMESPACE_NAME_##id,				\
	.arg_tokens_count = sizeof(token_name) / sizeof(token_name[0]),	\
	.arg_tokens = token_name,					\
	.create_attr_id = KPARSER_ATTR_CREATE_##id,			\
	.update_attr_id = KPARSER_ATTR_UPDATE_##id,			\
	.read_attr_id = KPARSER_ATTR_READ_##id,				\
	.delete_attr_id = KPARSER_ATTR_DELETE_##id,			\
	.rsp_attr_id = KPARSER_ATTR_RSP_##id				\

static const struct kparser_global_namespaces kparser_arg_namespace_md = {
	DEFINE_NAMESPACE_MEMBERS(METADATA, md_key_vals),
};

static const struct kparser_global_namespaces kparser_arg_namespace_ml = {
	DEFINE_NAMESPACE_MEMBERS(METALIST, mdl_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_proto_node = {
	DEFINE_NAMESPACE_MEMBERS(NODE_PROTO, proto_node_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_parse_node = {
	DEFINE_NAMESPACE_MEMBERS(NODE_PARSE, parse_node_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_proto_table = {
	DEFINE_NAMESPACE_MEMBERS(PROTO_TABLE, proto_table_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_proto_node = {
	DEFINE_NAMESPACE_MEMBERS(TLV_NODE_PROTO, tlv_proto_node_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_parse_node = {
	DEFINE_NAMESPACE_MEMBERS(TLV_NODE_PARSE, tlv_parse_node_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlvs_proto_node = {
	DEFINE_NAMESPACE_MEMBERS(TLVS_NODE_PROTO, tlvs_proto_node_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlvs_parse_node = {
	DEFINE_NAMESPACE_MEMBERS(TLVS_NODE_PARSE, tlvs_parse_node_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_proto_table = {
	DEFINE_NAMESPACE_MEMBERS(TLV_PROTO_TABLE, tlv_proto_table_key_vals),
};

static const struct kparser_global_namespaces kparser_arg_namespace_cond_exprs = {
	DEFINE_NAMESPACE_MEMBERS(CONDEXPRS, cond_exprs_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs_table = {
	DEFINE_NAMESPACE_MEMBERS(CONDEXPRS_TABLE, cond_exprs_table_key_vals),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs_tables = {
	DEFINE_NAMESPACE_MEMBERS(CONDEXPRS_TABLES, cond_exprs_tables_key_vals),
};

static const struct kparser_global_namespaces kparser_arg_namespace_parser = {
	DEFINE_NAMESPACE_MEMBERS(PARSER, parser_key_vals),
};

const struct kparser_global_namespaces *g_namespaces[] = {
	[KPARSER_NS_INVALID] = NULL,
	[KPARSER_NS_METADATA] = &kparser_arg_namespace_md,
	[KPARSER_NS_METALIST] = &kparser_arg_namespace_ml,

	[KPARSER_NS_NODE_PROTO] = &kparser_arg_namespace_proto_node,
	[KPARSER_NS_NODE_PARSE] = &kparser_arg_namespace_parse_node,
	[KPARSER_NS_PROTO_TABLE] = &kparser_arg_namespace_proto_table,

	[KPARSER_NS_TLV_NODE_PROTO] = &kparser_arg_namespace_tlv_proto_node,
	[KPARSER_NS_TLV_NODE_PARSE] = &kparser_arg_namespace_tlv_parse_node,
	[KPARSER_NS_TLVS_NODE_PROTO] = &kparser_arg_namespace_tlvs_proto_node,
	[KPARSER_NS_TLVS_NODE_PARSE] = &kparser_arg_namespace_tlvs_parse_node,
	[KPARSER_NS_TLV_PROTO_TABLE] = &kparser_arg_namespace_tlv_proto_table,

	[KPARSER_NS_FIELDS] = NULL, // TODO
	[KPARSER_NS_PARSER] = &kparser_arg_namespace_parser,
	[KPARSER_NS_CONDEXPRS] = &kparser_arg_namespace_cond_exprs,
	[KPARSER_NS_CONDEXPRS_TABLE] = &kparser_arg_namespace_cond_exprs_table,
	[KPARSER_NS_CONDEXPRS_TABLES] = &kparser_arg_namespace_cond_exprs_tables,
	[KPARSER_NS_MAX] = NULL,
};
