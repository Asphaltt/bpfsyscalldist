# bpfbpfsyscalldist

**bpfsyscalldist** is the tool to profile the BPF syscall.

## Build and run

```bash
# git clone https://github.com/Asphaltt/bpfsyscalldist.git
# cd bpfsyscalldist
# go generate && go build
# ./bpfsyscalldist -h
Usage of ./bpfsyscalldist:
      --pid uint32   filter pid
pflag: help requested
# ./bpfsyscalldist --pid 273496
2023/02/28 12:49:44 Attached kprobe(__sys_bpf)
2023/02/28 12:49:44 Attached kretprobe(__sys_bpf)
2023/02/28 12:49:44 Hit Ctrl-C to end.
^C
Histogram for syscall(BPF) cmd(BPF_PROG_LOAD) (sum 54):
     usecs               : count         distribution
         0 -> 1          : 0             |                                        |
         2 -> 3          : 0             |                                        |
         4 -> 7          : 0             |                                        |
         8 -> 15         : 0             |                                        |
        16 -> 31         : 0             |                                        |
        32 -> 63         : 0             |                                        |
        64 -> 127        : 0             |                                        |
       128 -> 255        : 0             |                                        |
       256 -> 511        : 0             |                                        |
       512 -> 1023       : 0             |                                        |
      1024 -> 2047       : 0             |                                        |
      2048 -> 4095       : 0             |                                        |
      4096 -> 8191       : 9             |***************                         |
      8192 -> 16383      : 10            |****************                        |
     16384 -> 32767      : 24            |****************************************|
     32768 -> 65535      : 8             |*************                           |
     65536 -> 131071     : 3             |*****                                   |
```

## Kprobes

`bpfsyscalldist` runs on kprobe/kretprobe `__sys_bpf`.

## License

Apache-2.0 license
