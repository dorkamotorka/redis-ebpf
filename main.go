package main

import (
	"log"
	"os"
	"unsafe"
	"bufio"
	"bytes"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go redis redis.c

var pgObjs redisObjects

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	pgObjs = redisObjects{}
	if err := loadRedisObjects(&pgObjs, nil); err != nil {
		log.Fatal(err)
	}

	w, err := link.Tracepoint("syscalls", "sys_enter_write", pgObjs.HandleWrite, nil)
	if err != nil {
		log.Fatal("link sys_enter_write tracepoint")
	}
	defer w.Close()

	r, err := link.Tracepoint("syscalls", "sys_enter_read", pgObjs.HandleRead, nil)
	if err != nil {
		log.Fatal("link sys_enter_read tracepoint")
	}
	defer r.Close()

	rexit, err := link.Tracepoint("syscalls", "sys_exit_read", pgObjs.HandleReadExit, nil)
	if err != nil {
		log.Fatal("link sys_exit_read tracepoint")
	}
	defer rexit.Close()

	L7EventsReader, err := perf.NewReader(pgObjs.L7Events, int(4096)*os.Getpagesize())
	if err != nil {
		log.Fatal("error creating perf event array reader")
	}

	for {
		var record perf.Record
		err := L7EventsReader.ReadInto(&record)
		if err != nil {
			log.Print("error reading from perf array")
		}

		if record.LostSamples != 0 {
			log.Printf("lost samples l7-event %d", record.LostSamples)
		}

		// TODO: investigate why this is happening
		if record.RawSample == nil || len(record.RawSample) == 0 {
			log.Print("read sample l7-event nil or empty")
			return
		}

		l7Event := (*bpfL7Event)(unsafe.Pointer(&record.RawSample[0]))
		protocol := L7ProtocolConversion(l7Event.Protocol).String()

		if (protocol == "REDIS") {
			reader := bufio.NewReader(bytes.NewReader(l7Event.Payload[:l7Event.PayloadSize]))

			value, err := ParseRedisProtocol(reader)
			if err != nil {
				log.Println("Error:", err)
			} else {
				log.Printf("%s\n", value)
			}
		}
	}
}