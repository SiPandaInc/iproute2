/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* kparser.h - KPARSER Interface */

#ifndef _LINUX_KPARSER_H
#define _LINUX_KPARSER_H

#include <linux/string.h>
#include <linux/types.h>
#include <stdbool.h>

#define BITS_IN_BYTE	8
#define BITS_IN_U32	(sizeof(__u32) * BITS_IN_BYTE)
#define SetBit(A,k)	(A[(k)/BITS_IN_U32] |= (1 << ((k) % BITS_IN_U32)))
#define ClearBit(A,k)	(A[(k)/BITS_IN_U32] &= ~(1 << ((k) % BITS_IN_U32)))
#define TestBit(A,k)    (1 & (A[(k)/BITS_IN_U32] >> ((k) % BITS_IN_U32)))

/* NETLINK_GENERIC related info */
#define KPARSER_GENL_NAME	"kparser"
#define KPARSER_GENL_VERSION	0x1

#define KPARSER_ERR_STR_LEN_MAX 256
#define KPARSER_MAX_U16_STR_LEN 8
#define KPARSER_MAX_U64_STR_LEN 16

enum kparser_arg_val_type {
	KPARSER_ARG_VAL_STR,
	KPARSER_ARG_VAL_U16,
	KPARSER_ARG_VAL_U64,
	KPARSER_ARG_VAL_BOOL,
	KPARSER_ARG_VAL_FLAG,
	KPARSER_ARG_VAL_SET,
	KPARSER_ARG_VAL_INVALID
};

#define KPARSER_SET_VAL_LEN_MAX 64

struct kparser_arg_set {
	const char *set_value_str;
	__u64 set_value_enum;
};

struct kparser_arg_key_val_token {
	struct {
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
			};
		};
	};
	const struct kparser_arg_key_val_token *default_template_token;
};

enum kparser_global_namespace_ids {
	KPARSER_NS_INVALID,
	md,
	mdl,
	node,
	proto,
	fields,
	parser,
	condexprs,
	KPARSER_NS_MAX
};

enum kparser_md_type {
	KPARSER_MD_INVALID,
	KPARSER_MD_HDRDATA,
	KPARSER_MD_HDRLEN,
	KPARSER_MD_OFFSET,
	KPARSER_MD_NUMENCAPS,
	KPARSER_MD_NUMNODES,
	KPARSER_MD_TIMESTAMP,
	KPARSER_MD_MAX
};

struct kparser_global_namespaces {
	enum kparser_global_namespace_ids name_space_id;
	const char *name;
	size_t arg_tokens_count;
	const struct kparser_arg_key_val_token *arg_tokens; 
	int req_attr_id;
	int rsp_attr_id;
	int cmd_buf_size;
};

enum {
	KPARSER_ATTR_UNSPEC,

	KPARSER_ATTR_CREATE_MD,				/* NLA_BINARY */
	KPARSER_ATTR_CREATE_MD_RSP,			/* NLA_BINARY */

	KPARSER_ATTR_CREATE_MDL,			/* NLA_BINARY */
	KPARSER_ATTR_CREATE_MDL_RSP,			/* NLA_BINARY */

	KPARSER_ATTR_CREATE_NODE,			/* NLA_BINARY */
	KPARSER_ATTR_CREATE_NODE_RSP,			/* NLA_BINARY */

	KPARSER_ATTR_CREATE_TBL,			/* NLA_BINARY */
	KPARSER_ATTR_CREATE_TBL_RSP,			/* NLA_BINARY */

	KPARSER_ATTR_CREATE_TBL_ENT,			/* NLA_BINARY */
	KPARSER_ATTR_CREATE_TBL_ENT_RSP,		/* NLA_BINARY */

	KPARSER_ATTR_CREATE_PARSER,			/* NLA_BINARY */
	KPARSER_ATTR_CREATE_PARSER_RSP,			/* NLA_BINARY */

	KPARSER_ATTR_DELL_ALL,				/* NLA_BINARY */
	KPARSER_ATTR_DELL_ALL_RSP,			/* NLA_BINARY */

	KPARSER_ATTR_LIST_PARSER,			/* NLA_BINARY */
	KPARSER_ATTR_LIST_PARSER_RSP,			/* NLA_BINARY */


	__KPARSER_ATTR_MAX,
};

#define KPARSER_ATTR_MAX		(__KPARSER_ATTR_MAX - 1)

#include <linux/kernel.h>

#ifndef KERNEL_MOD
// TODO remove these
typedef int8_t  s8;
typedef uint8_t  u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint16_t u32;
typedef int64_t s64;
typedef uint64_t u64;
#endif

// TODO: Use __u64 in both user and kernel spaces
// __u64

enum {
	KPARSER_CMD_UNSPEC,
	KPARSER_CMD_ADD,
	KPARSER_CMD_GET,
	KPARSER_CMD_DEL,
	__KPARSER_CMD_MAX,
};

#define KPARSER_CMD_MAX	(__KPARSER_CMD_MAX - 1)

#define KPARSER_INVALID_ID 0xffff

#define KPARSER_USER_ID_MIN 0
#define KPARSER_USER_ID_MAX 0x8000
#define KPARSER_KMOD_ID_MIN 0x8001
#define KPARSER_KMOD_ID_MAX 0xfffe
#define KPARSER_MAX_NAME 128
#define KPARSER_MAX_DIGIT_STR_LEN 16
#define KPARSER_DEF_NAME_PREFIX "kparser_default_name"

// prepend kparser_
struct kparser_hkey {
	u16 id;
	char name[KPARSER_MAX_NAME];
};

#define PANDA_PARSER_METADATA_BYTE_EXTRACT	0
#define PANDA_PARSER_METADATA_NIBB_EXTRACT	1
#define PANDA_PARSER_METADATA_CONSTANT_SET	2
#define PANDA_PARSER_METADATA_CONTROL_SET	3

/* Kparser generic metadata
 *
 * Contains an array of kparser specific (user defined) metadata structures.
 * Meta data structures are defined specifically for each parser.
 * An instance of this metadata is a frame. One frame is used for each
 * level of encapsulation. When the number of encapsulation layers exceeds
 * max_num_frame then last frame is reused and previous data is overwritten.
 *	encaps: Number of encapsulation protocol encountered.
 *	max_frame_num: Maximum number of frames. One frame is used for each
 *		level of encapulation. When the number of encapsulation
 *		layers exceeds this value the last frame is reuse used
 *	frame_size: The size in bytes of each metadata frame
 *	frame_data: Contains max_frame_num metadata frames
 */
struct kparser_metadata {
	uint encaps;
	uint max_frame_num;
	size_t meta_meta_data_size;
	size_t frame_size;

	/* Application specific meta metadata and metadata frames */
	__u8 frame_data[0]; // __aligned(8);
};

struct kparser_md_xtrct_cnf {
        union {
                struct {
                        __u8 code: 4;
                        __u8 flags: 4;
                        __u8 dst_off;
                        __u8 src_off;
                        __u8 length;
                } gen;
                struct {
                        __u8 code: 4;
                        __u8 e_bit: 1;
                        __u8 flags: 3;
                        __u8 dst_off;
                        __u8 src_off;
                        __u8 length;
                } byte;
                struct {
                        __u8 code: 4;
                        __u8 e_bit: 1;
                        __u8 n_bit: 1;
                        __u8 flags: 2;
                        __u8 dst_off;
                        __u8 src_off;
                        __u8 length;
                } nibb;
                struct {
                        __u8 code: 4;
                        __u8 l_bit: 1;
                        __u8 o_bit: 1;
                        __u8 flags: 2;
                        __u8 dst_off;
                        __u8 data_low;
                        __u8 data_high;
                } const_set;
                struct {
                        __u8 code: 4;
                        __u8 flags: 4;
                        __u8 dst_off;
                        __u8 data_select;
                        __u8 rsvd;
                } control;
                __u32 val;
        };
};

struct kparser_arg_md {
	struct kparser_hkey key;
	__u16 soff;
	__u16 doff;
	size_t len;
	enum kparser_md_type type;
	struct kparser_md_xtrct_cnf config;
	struct kparser_hkey array_hkey;
	__u16 array_doff;
	struct kparser_hkey array_counter_id;
};

struct kparser_arg_mdl {
	struct kparser_hkey key;
	struct kparser_hkey mdkey; // mandatory one
	u16 mdkeys_count; // optional ones in a var. array
	struct kparser_hkey mdkeys[0];
};

struct kparser_proto_tbl_ent {
	struct kparser_hkey key;
	u16 idx_key_map;
	struct kparser_hkey node_key;
};

enum kparser_tbl_default_lbls {
	KPARSER_STOP_OKAY = 0,
};

struct kparser_nxt_proto_key {
        __u16 src_off;
        __u16 mask;
        __u8 size;
        __u8 right_shift;
};

struct kparser_arg_proto_tbl {
	struct kparser_hkey key;
	enum kparser_tbl_default_lbls def_val;
	struct kparser_proto_tbl_ent tbl_ent;
	struct kparser_nxt_proto_key pkeymap;
	// unused
	u16 tbl_ents_cnt;
	char tbl_ents[0];
};

/* Kparse protocol node types */
enum kparser_node_type {
	/* Plain node, no super structure */
	KPARSER_NODE_TYPE_PLAIN,
	/* TLVs node with super structure for TLVs */
	KPARSER_NODE_TYPE_TLVS,
	/* Flag-fields with super structure for flag-fields */
	KPARSER_NODE_TYPE_FLAG_FIELDS,
	/* Parse node */
	KPARSER_NODE_TYPE_PARSER,
	/* Protocol node */
	KPARSER_NODE_TYPE_PROTO,
	/* It represents the limit value */
	KPARSER_NODE_TYPE_MAX,
};

struct kparser_parameterized_len {
        __u16 src_off;
        __u8 size;
        bool endian;
        __u32 mask;
        __u8 right_shift;
        __u8 multiplier;
        __u8 add_value;
};

struct kparser_arg_node {
	struct kparser_hkey key;
	enum kparser_node_type type;
	u8 encap;
	u8 overlay;
	u16 minlen;
	u16 nxtoffset;
	u16 nxtlength;
	struct kparser_parameterized_len plen;
	struct kparser_hkey prot_tbl_key;
	struct kparser_hkey mdl_key;
};

/* Kparser type codes */
enum kparser_type {
	/* Use non-optimized loop panda parser algorithm */
	kparser_generic,
	/* Use optimized, generated, parser algorithm  */
	kparser_optimized,
	/* It represents the limit value */
	kparser_max,
};

/* Configuration for a Kparser */
struct kparser_config {
	u16 flags;
	u16 max_nodes;
	u16 max_encaps;
	enum kparser_type type;
};

struct kparser_arg_parser {
	struct kparser_hkey key;
	struct kparser_config config;
	// TODO: support for multiple root nodes?
	struct kparser_hkey root_node_key;
};

#define KPARSER_ERR_STR_MAX_LEN 256

struct kparser_config_cmd {
	enum kparser_global_namespace_ids namespace_id;
	union {
		struct kparser_arg_md md_conf;
	};
};

struct kparser_cmd_rsp_hdr {
	s32 op_ret_code;
	struct kparser_hkey key;
	u8 err_str_buf[KPARSER_ERR_STR_MAX_LEN];
};

static inline bool kparser_hkey_empty(const struct kparser_hkey *key)
{
	return (key == NULL || ((key->id == KPARSER_INVALID_ID) &&
			(key->name[0] == '\0')));
}

#endif /* _LINUX_KPARSER_H */
