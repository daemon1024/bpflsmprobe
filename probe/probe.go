package probe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf probe.bpf.c -target bpfel -type event -- -I/usr/include/bpf -O2 -g -D__TARGET_ARCH_x86

type eventBPF struct {
	Exec bool
}

func CheckBPFLSMSupport() error {
	// Check if LSM support is enabled in the kernel

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.AttachLSM(link.LSMOptions{Program: objs.TestMemfd})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	log.Println("Waiting for events..")

	var event eventBPF
	go func() {
		fd, err := unix.MemfdCreate("trigger_memfd", 0)
		if err != nil {
			fmt.Printf("Error creating memfd: %v\n", err)
			return
		}
		defer unix.Close(fd)
	}()

	rd.SetDeadline(time.Now().Add(1 * time.Second))
	record, err := rd.Read()
	if err != nil {
		return err
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("parsing ringbuf event: %s", err)
	}
	log.Printf("event: %+v", event)

	return nil

}
