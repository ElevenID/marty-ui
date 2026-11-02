//go:build linux

package openbaocontrol

import (
	"context"
	"errors"
	"net/http"
)

var errStaticSeal = errors.New("OpenBao static-seal status or custody refused")

// StaticObservation separates a reachable listener from usable initialized
// state. Observation never initializes, unseals, restarts, or changes a seal.
type StaticObservation struct {
	Schema            string `json:"schema"`
	ListenerAvailable bool   `json:"listener_available"`
	SealType          string `json:"seal_type"`
	Initialized       bool   `json:"initialized"`
	Sealed            bool   `json:"sealed"`
	RecoverySeal      bool   `json:"recovery_seal"`
	UnsealedReady     bool   `json:"unsealed_ready"`
	ClusterID         string `json:"cluster_id,omitempty"`
	InstallationReady bool   `json:"installation_ready"`
}

func staticStatus(ctx context.Context, client *http.Client, requireReady bool) (StaticObservation, error) {
	observation := StaticObservation{Schema: "elevenid.openbao-static-readiness/v1"}
	var status struct {
		Type         string `json:"type"`
		Initialized  *bool  `json:"initialized"`
		Sealed       *bool  `json:"sealed"`
		RecoverySeal *bool  `json:"recovery_seal"`
		Migration    *bool  `json:"migration"`
		ClusterID    string `json:"cluster_id"`
	}
	if apiRequest(ctx, client, http.MethodGet, "sys/seal-status", "", nil, &status) != nil ||
		status.Initialized == nil || status.Sealed == nil || status.RecoverySeal == nil || status.Migration == nil {
		return observation, errStaticSeal
	}
	observation.ListenerAvailable = true
	observation.SealType = status.Type
	observation.Initialized = *status.Initialized
	observation.Sealed = *status.Sealed
	observation.RecoverySeal = *status.RecoverySeal
	observation.ClusterID = status.ClusterID
	if status.Type != "static" || !*status.RecoverySeal || *status.Migration ||
		(!*status.Initialized && (!*status.Sealed || status.ClusterID != "")) ||
		(*status.Initialized && !*status.Sealed && !uuidPattern.MatchString(status.ClusterID)) {
		return observation, errStaticSeal
	}
	observation.UnsealedReady = *status.Initialized && !*status.Sealed
	if requireReady && !observation.UnsealedReady {
		return observation, errStaticSeal
	}
	return observation, nil
}

// ObserveStatic uses only the fixed, ownership-checked Unix endpoint. The
// static seal key is mounted in OpenBao alone and is never read by this helper.
func ObserveStatic(ctx context.Context, requireReady bool) (StaticObservation, error) {
	client, err := NewClient()
	if err != nil {
		return StaticObservation{Schema: "elevenid.openbao-static-readiness/v1"}, errStaticSeal
	}
	defer closeClient(client)
	return staticStatus(ctx, client, requireReady)
}
