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
#define KPARSER_CONFIG_MAX_KEYS		64 

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
	KPARSER_ARG_VAL_HYB_IDX,
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
};
#endif /* _KPARSER_COMMON_H */
