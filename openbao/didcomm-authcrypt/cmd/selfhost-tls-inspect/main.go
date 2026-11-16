// selfhost-tls-inspect emits a read-only public observation of the installer's
// enrolled local TLS identity. It performs no API request or recovery mutation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ElevenID/marty-ui/openbao/didcomm-authcrypt/internal/openbaocontrol"
)

func main() {
	installation := flag.String("installation-id", "", "owned installation UUID")
	flag.Parse()
	if flag.NArg() != 0 {
		fail()
	}
	observation, err := openbaocontrol.InspectTLS(*installation)
	if err != nil {
		fail()
	}
	if json.NewEncoder(os.Stdout).Encode(observation) != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "OpenBao TLS inspection refused; retained authority or file binding unavailable")
	os.Exit(1)
}
