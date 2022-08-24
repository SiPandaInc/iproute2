/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* kparser.h - kParser Interface */

#ifndef _KPARSER_COMMON_H
#define _KPARSER_COMMON_H

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>

#define KPARSER_MAX_STR_LEN_U8		6
#define KPARSER_MAX_STR_LEN_U16 	8
#define KPARSER_MAX_STR_LEN_U32 	12
#define KPARSER_MAX_STR_LEN_U64 	16

#define KPARSER_SET_VAL_LEN_MAX		64
#define KPARSER_DEFAULT_U16_MASK	0xffff
#define KPARSER_DEFAULT_U32_MASK	0xffffffff
#define KPARSER_CONFIG_MAX_KEYS		128 

enum kparser_arg_val_type {
	KPARSER_ARG_VAL_STR,
	KPARSER_ARG_VAL_U8,
	KPARSER_ARG_VAL_U16,
	KPARSER_ARG_VAL_U32,
	KPARSER_ARG_VAL_U64,
	KPARSER_ARG_VAL_BOOL,
	KPARSER_ARG_VAL_FLAG,
	KPARSER_ARG_VAL_SET,
	KPARSER_ARG_VAL_ARRAY,
	KPARSER_ARG_VAL_HYB_KEY_NAME,
	KPARSER_ARG_VAL_HYB_KEY_ID,
	KPARSER_ARG_VAL_S32,
	KPARSER_ARG_VAL_INVALID
};

struct kparser_arg_set {
	const char *set_value_str;
	__u64 set_value_enum;
};

enum kparser_print_id {
	KPARSER_PRINT_INT,
	KPARSER_PRINT_HEX,
};

enum {
	op_create = 0,
	op_read,
	op_update,
	op_delete,
	op_lock,
	op_unlock,
	op_max
};

int do_cli(int nsid, int op, int argc, int *argidx, const char **argv,
		const char *hybrid_token, bool preprocess_done,
		bool undesired_key_check);

typedef int kparser_ns_arg_pre_handler(
		int nsid, int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const char *tbn, __u16 tbid);

typedef int kparser_ns_arg_post_handler(
		const void *ns,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const int *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg);

struct kparser_global_namespaces {
	enum kparser_global_namespace_ids name_space_id;
	const char *name;
	const char *alias;
	const char *description;
	size_t arg_tokens_count;
	const struct kparser_arg_key_val_token *arg_tokens; 
	int create_attr_id;
	int update_attr_id;
	int read_attr_id;
	int delete_attr_id;
	int rsp_attr_id;
	kparser_ns_arg_pre_handler  *custom_do_cli;
	kparser_ns_arg_post_handler *post_process_handler;
};

struct kparser_arg_key_val_token {
	enum kparser_arg_val_type type;
	const char *key_name;
	bool mandatory;
	bool semi_optional;
	int other_mandatory_idx;
	bool immutable;
	size_t str_arg_len_max;
	size_t w_offset;
	size_t w_len;
	union {
		struct {
			size_t default_val_size;
			const void *default_val;
		};
		struct {
			size_t value_set_len;
			const struct kparser_arg_set *value_set;
			__u64 def_value_enum;
		};
		struct {
			__u64 min_value;
			__u64 def_value;
			__u64 max_value;
			enum kparser_print_id print_id;
		};
	};
	struct {
		enum kparser_arg_val_type elem_type;
		size_t elem_counter;
		size_t elem_size;
		size_t offset_adjust;
	};
	const char *help_msg;
	const struct kparser_arg_key_val_token *default_template_token;
	const char *incompatible_keys[KPARSER_CONFIG_MAX_KEYS];
	const char *json_recursive_object_start_name;
	const char *json_recursive_object_end_name;
	bool dontreport;
};
#endif /* _KPARSER_COMMON_H */
