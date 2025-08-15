# Learning eBPF

Learning-ebpf book's example repository

## Prerequisites

- `limactl` to launch a linux vm

## Launching examples

```shell
# Launch a new ubuntu vm
$ cd learning-ebpf
$ limactl start ebpf --mount-writable
$ limactl shell ebpf
$ sudo apt install build-essential clang libbpf-dev libelf-dev zlib1g-dev pkg-config clang llvm bpfcc-tools linux-headers-$(uname -r) python3-pip
```

