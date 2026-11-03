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
		fail(nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	receipt, err := openbaocontrol.InitializeStatic(ctx, *installation, *attempt)
	if err != nil {
		fail(err)
	}
	if json.NewEncoder(os.Stdout).Encode(receipt) != nil {
		fail(nil)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "OpenBao static-seal initialization refused; preserve the pending setup and private outputs")
	if class := openbaocontrol.StaticInitFailureClass(err); class != "" {
		fmt.Fprintf(os.Stderr, "OpenBao static-seal failure_class=%s; initialization outcome remains uncertain\n", class)
	}
	os.Exit(1)
}
