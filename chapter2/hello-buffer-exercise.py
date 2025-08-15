#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output);

struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int hello(void *ctx) {
    struct data_t data = {};
    char message[12] = "";

    data.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if (data.pid % 2 == 0) {
        __builtin_strcpy(message, "Hello Even");
    } else {
        __builtin_strcpy(message, "Hello Odd");
    }


    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel_str(&data.message, sizeof(data.message), message);
    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

def print_event(cpu, data, size):
    event = b["output"].event(data)
    print(f"PID: {event.pid}, UID: {event.uid}, Command: {event.command.decode('utf-8')}, Message: {event.message.decode('utf-8')}")

b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()