// selfhost-static-init initializes only a fresh installer-owned static-seal
// node. It never reads the static seal key or submits an unseal operation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ElevenID/marty-ui/openbao/didcomm-authcrypt/internal/openbaocontrol"
)

func main() {
	installation := flag.String("installation-id", "", "owned installation UUID")
	attempt := flag.String("attempt-id", "", "recorded fresh initialization attempt UUID")
	flag.Parse()
	if flag.NArg() != 0 {
		fail()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	receipt, err := openbaocontrol.InitializeStatic(ctx, *installation, *attempt)
	if err != nil || json.NewEncoder(os.Stdout).Encode(receipt) != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "OpenBao static-seal initialization refused; preserve the pending setup and private outputs")
	os.Exit(1)
}
