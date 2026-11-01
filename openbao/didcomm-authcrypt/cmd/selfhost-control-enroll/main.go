// selfhost-control-enroll establishes the fixed local recovery authority during
// the owned fresh installation. Existing or uncertain work is never adopted.
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
	attempt := flag.String("attempt-id", "", "recorded setup attempt UUID")
	flag.Parse()
	if flag.NArg() != 0 {
		fail()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	receipt, err := openbaocontrol.Enroll(ctx, *installation, *attempt)
	if err != nil {
		fail()
	}
	if json.NewEncoder(os.Stdout).Encode(receipt) != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "OpenBao control enrollment refused; preserve the pending setup and private outputs")
	os.Exit(1)
}
