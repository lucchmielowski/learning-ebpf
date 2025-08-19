//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct user_msg_t {
	char message[12];
};

struct data_t {
	int pid;
	int uid;
	char command[16];
	char message[12];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct user_msg_t);
} user_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} output SEC(".maps");

SEC("kprobe/sys_execve")
int hello(struct trace_event_raw_sys_enter *ctx) {
	char default_msg[12] = "Hello World";
	struct data_t data = {};

	data.pid = bpf_get_current_pid_tgid() >> 32;
	data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	bpf_get_current_comm(&data.command, sizeof(data.command));

	struct user_msg_t *p = bpf_map_lookup_elem(&user_config, &data.uid);
	if (p) {
		__builtin_memcpy(data.message, p->message, sizeof(data.message));
	} else {
		__builtin_memcpy(data.message, default_msg, sizeof(data.message));
	}

	bpf_ringbuf_output(&output, &data, sizeof(data), 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";