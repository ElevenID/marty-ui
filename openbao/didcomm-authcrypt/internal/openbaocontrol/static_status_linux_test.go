//go:build linux

package openbaocontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestStaticReadinessOnlyObservesSealState(t *testing.T) {
	for _, state := range []string{"uninitialized", "sealed", "ready", "shamir", "migrating", "missing-recovery", "missing-migration", "bad-cluster"} {
		t.Run(state, func(t *testing.T) {
			body := map[string]any{
				"type": "static", "initialized": true, "sealed": false, "recovery_seal": true,
				"migration": false, "cluster_id": testCluster,
			}
			switch state {
			case "uninitialized":
				body["initialized"], body["sealed"] = false, true
				delete(body, "cluster_id")
			case "sealed":
				body["sealed"] = true
				delete(body, "cluster_id")
			case "shamir":
				body["type"], body["recovery_seal"] = "shamir", false
			case "migrating":
				body["migration"] = true
			case "missing-recovery":
				delete(body, "recovery_seal")
			case "missing-migration":
				delete(body, "migration")
			case "bad-cluster":
				body["cluster_id"] = "not-a-cluster-id"
			}
			requests := 0
			path, expected := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests++
				if request.Method != http.MethodGet || request.URL.Path != "/v1/sys/seal-status" || request.Header.Get("X-Vault-Token") != "" || request.ContentLength > 0 {
					t.Error("readiness attempted a mutation or credential use")
					http.Error(w, "refused", http.StatusForbidden)
					return
				}
				_ = json.NewEncoder(w).Encode(body)
			}))
			client, err := newClientAt(path, expected)
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient(client)
			listener, listenerErr := staticStatus(context.Background(), client, false)
			ready, readyErr := staticStatus(context.Background(), client, true)
			if requests != 2 || listener.InstallationReady || ready.InstallationReady || ready.UnsealedReady != (state == "ready") ||
				(readyErr == nil) != (state == "ready") || (listenerErr == nil) != (state == "uninitialized" || state == "sealed" || state == "ready") {
				t.Fatal("static readiness confused listener availability, seal mode or initialized readiness")
			}
		})
	}
}
