// selfhost-openbao-ready observes the fresh installer's static-seal node.
// It has no unseal, initialization, key-file, restart, or network fallback path.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ElevenID/marty-ui/openbao/didcomm-authcrypt/internal/openbaocontrol"
)

func main() {
	listener := flag.Bool("check-listener", false, "observe the static-seal listener without changing it")
	ready := flag.Bool("check-ready", false, "require initialized and unsealed static-seal readiness")
	watch := flag.Bool("watch", false, "watch static-seal readiness without changing node state")
	flag.Parse()
	modes := 0
	for _, enabled := range []bool{*listener, *ready, *watch} {
		if enabled {
			modes++
		}
	}
	if flag.NArg() != 0 || modes != 1 {
		fail()
	}
	if !*watch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		observation, err := openbaocontrol.ObserveStatic(ctx, *ready)
		if json.NewEncoder(os.Stdout).Encode(observation) != nil || err != nil {
			fail()
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var previous []byte
	for ctx.Err() == nil {
		request, cancel := context.WithTimeout(ctx, 5*time.Second)
		observation, _ := openbaocontrol.ObserveStatic(request, true)
		cancel()
		current, err := json.Marshal(observation)
		if err != nil {
			fail()
		}
		if !bytes.Equal(current, previous) {
			if _, err := fmt.Fprintln(os.Stdout, string(current)); err != nil {
				fail()
			}
			previous = current
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "OpenBao static-seal readiness is unavailable")
	os.Exit(1)
}
