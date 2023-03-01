package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"bpfsyscalldist/pkg/histogram"
	"bpfsyscalldist/pkg/lodash"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	flag "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang syscall ./ebpf/bpfsyscalldist.c -- -I./ebpf/headers -Wall -D__TARGET_ARCH_x86

func main() {
	var filterPid uint32
	flag.Uint32Var(&filterPid, "pid", 0, "filter pid")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit memlock: %v", err)
	}

	spec, err := loadSyscall()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"filter_pid": filterPid,
	}); err != nil {
		log.Fatalf("Failed to rewrite const: %v", err)
	}

	var obj syscallObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load bpf obj: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load bpf obj: %v", err)
	}

	if k, err := link.Kprobe("__sys_bpf", obj.K_sysBpf, nil); err != nil {
		log.Fatalf("Failed to attach kprobe(__sys_bpf): %v", err)
	} else {
		defer k.Close()
		log.Printf("Attached kprobe(__sys_bpf)")
	}

	if kr, err := link.Kretprobe("__sys_bpf", obj.KrSysBpf, nil); err != nil {
		log.Fatalf("Failed to attach kretprobe(__sys_bpf): %v", err)
	} else {
		defer kr.Close()
		log.Printf("Attached kretprobe(__sys_bpf)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Print("Hit Ctrl-C to end\n")

	<-ctx.Done()

	printHist(obj.Hists, "BPF")
}

const (
	maxSlots = 36
)

type slot struct {
	Slots [maxSlots]uint64
}

func printHist(m *ebpf.Map, syscall string) {
	val := make([]slot, runtime.NumCPU())

	fmt.Println()

	for key := uint32(BPF_MAP_CREATE); key < uint32(_BPF_MAX); key++ {
		err := m.Lookup(key, &val)
		if err != nil {
			log.Printf("Failed to lookup key(%s): %v", BpfCmd(key), err)
			return
		}

		var slot slot
		for _, v := range val {
			for i, n := range v.Slots[:] {
				slot.Slots[i] += n
			}
		}

		sum := lodash.Sum(slot.Slots[:])
		if sum == 0 {
			continue
		}

		fmt.Printf("Histogram for syscall(%s) cmd(%s) (sum %d):\n", syscall, BpfCmd(key), sum)
		histogram.PrintLog2Hist(slot.Slots[:], "usecs")
		fmt.Println()
	}
}
