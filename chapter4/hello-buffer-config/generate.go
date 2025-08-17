package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux hellobufferconfig hello-buffer-config.c

// TODO: Add user-space code to load the BPF program and interact with it.