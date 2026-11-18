// selfhost-tls-recover is the installer's fixed, in-container certificate
// replacement operation. The installation owner handles locking and SIGHUP.
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
	attempt := flag.String("attempt-id", "", "recorded maintenance attempt UUID")
	flag.Parse()
	if flag.NArg() != 0 {
		fail()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	receipt, err := openbaocontrol.Recover(ctx, *installation, *attempt)
	if err != nil {
		fail()
	}
	if json.NewEncoder(os.Stdout).Encode(receipt) != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "OpenBao TCP certificate recovery refused; preserve the pending operation")
	os.Exit(1)
}
