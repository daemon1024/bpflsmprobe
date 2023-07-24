//go:build linux
// +build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/daemon1024/bpflsmprobe/probe"
)

func main() {

	stopper := make(chan os.Signal, 1)

	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := probe.CheckBPFLSMSupport(); err != nil {
		log.Fatalf("probeBPFLSMSupport: %v", err)
	} else {
		log.Println("probeBPFLSMSupport: success")
	}
}
