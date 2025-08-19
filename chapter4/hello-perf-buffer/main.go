package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type Event struct {
	Pid     uint32
	Uid     uint32
	Comm    [16]byte
	Message [12]byte
}

type UserMsg struct {
	Message [12]byte
}

func cStr12(s string) (out [12]byte) {
	// Copy 11 bytes leave 1 byte for NUL
	n := copy(out[:11], s)
	out[n] = 0
	return out
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	fn := "sys_execve"

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs helloObjects

	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(fn, objs.Hello, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	var rootMsg = UserMsg{Message: cStr12("Hello root!")}
	var uid501Msg = UserMsg{Message: cStr12("Hello 501!")}

	must(objs.UserConfig.Put(uint32(0), rootMsg))
	must(objs.UserConfig.Put(uint32(501), uid501Msg))

	perfCPUBuffer := 1 << 20 // 1MiB per CPU
	rd, err := perf.NewReader(objs.Output, perfCPUBuffer)
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				return
			}

			if rec.LostSamples != 0 {
				log.Printf("perf: Dropped %d samples", rec.LostSamples)
				continue
			}

			var e Event
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
				log.Printf("decode: %v", err)
				continue
			}
			comm := string(e.Comm[:bytes.IndexByte(e.Comm[:], 0)])
			msg := string(e.Message[:bytes.IndexByte(e.Message[:], 0)])
			fmt.Printf("[%s] pid=%d uid=%d message=%q comm=%q\n", time.Now().Format(time.RFC3339), e.Pid, e.Uid, msg, comm)
		}
	}()

	fmt.Println("listening… press Ctrl-C to quit")
	<-ctx.Done()
}
