/* SPDX-License-Identifier: LGPL-2.1 */
/* Copyright (c) 2018 Facebook */

#ifndef __BPF_BTF_H
#define __BPF_BTF_H

#include <linux/types.h>

#define BTF_ELF_SEC ".BTF"
#define BTF_EXT_ELF_SEC ".BTF.ext"

struct btf;
struct btf_ext;
struct btf_type;

struct btf_ext_header {
	__u16   magic;
	__u8    version;
	__u8    flags;
	__u32   hdr_len;

	/* All offsets are in bytes relative to the end of this header */
	__u32   func_info_off;
	__u32   func_info_len;
	__u32   line_info_off;
	__u32   line_info_len;
};

struct btf_sec_func_info {
	__u32   sec_name_off;
	__u32   num_func_info;
	/* followed by num_func_info number of bpf_func_info records */
	__u8	data[0];
};

struct btf_sec_line_info {
	__u32	sec_name_off;
	__u32	num_line_info;
};

typedef int (*btf_print_fn_t)(const char *, ...)
	__attribute__((format(printf, 1, 2)));

void btf__free(struct btf *btf);
struct btf *btf__new(__u8 *data, __u32 size, btf_print_fn_t err_log);
__s32 btf__find_by_name(const struct btf *btf, const char *type_name);
const struct btf_type *btf__type_by_id(const struct btf *btf, __u32 id);
__s64 btf__resolve_size(const struct btf *btf, __u32 type_id);
int btf__resolve_type(const struct btf *btf, __u32 type_id);
int btf__fd(const struct btf *btf);
const char *btf__name_by_offset(const struct btf *btf, __u32 offset);
int btf_get_from_id(__u32 id, struct btf **btf);
struct btf_ext *btf_ext__new(__u8 *data, __u32 size, btf_print_fn_t err_log);
void btf_ext__free(struct btf_ext *btf_ext);
int btf_ext_reloc_init(struct btf *btf, struct btf_ext *btf_ext,
		       const char *sec_name, __u32 *btf_fd,
		       void **func_info, __u32 *func_info_len);
int btf_ext_reloc(struct btf *btf, struct btf_ext *btf_ext,
		  const char *sec_name, __u32 insns_cnt, void **func_info,
		  __u32 *func_info_len);
#endif
