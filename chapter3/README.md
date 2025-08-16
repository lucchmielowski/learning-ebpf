# Chapter 3

## Useful commands

```sh
# Load program
bpftool prog load <program_name>.o /sys/fs/bpf/<program_name>

# List all programs
bpftool prog list

# Show program description (if loaded in kernel)
bpftool prog show id <id> (--pretty)
bpftool prog show name <name>
bpftool prog show tag <tag>
bpftool prog show pinned <prog_file_path>

# Dump eBPF bytecode
bpftool prog dump <xlated|jited> name <program>

# Attach program to event
bpftool net attach xdp id <program_id> dev <iface>

# List network-attached BPF programs
bpftool net list

# List global variable maps 
bpftool map list
bpftool map dump name <map_name>

# Unload the program 
rm /sys/fs/bpf/<program>
```