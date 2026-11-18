// selfhost-root-retire revokes and removes only the exactly retained initial
// root after the host has recorded its independently validated release gate.
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
	attempt := flag.String("attempt-id", "", "immutable retirement attempt UUID")
	intent := flag.String("intent-sha256", "", "public host eligibility intent digest")
	flag.Parse()
	if flag.NArg() != 0 {
		fail()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := openbaocontrol.RetireInitialRoot(ctx, *installation, *attempt, *intent)
	if err != nil {
		fail()
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		fail()
	}
}
func fail() {
	fmt.Fprintln(os.Stderr, "initial OpenBao root retirement incomplete; preserve its exact pending attempt and original authority")
	os.Exit(1)
}
