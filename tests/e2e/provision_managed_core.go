//go:build linux

// Test-only setup of a disposable ElXray Stage 3 managed journal.
//
// Invoked from the matching ElXray module checkout by the Control E2E suite:
// it intentionally calls the production journal API rather than generating
// synthetic anchor files or disabling the kernel's operation fence.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/common/elxjournal"
)

func provision(resource, state, path, store string) error {
	if filepath.Dir(state) != filepath.Dir(path) ||
		!strings.Contains(filepath.Dir(path), "elx-live-scheduler-e2e-") {
		return errors.New("journal is not under disposable E2E directory")
	}
	id, err := uuid.Parse(store)
	if err != nil || id == uuid.Nil || id.String() != store {
		return errors.New("invalid store UUID")
	}
	baseline, err := json.Marshal(struct {
		Version int
		StoreID string
	}{Version: 2, StoreID: store})
	if err != nil {
		return err
	}
	if err := os.WriteFile(state, baseline, 0o600); err != nil {
		return err
	}
	if err := elxjournal.Provision(path, store); err != nil {
		return err
	}
	journal, err := elxjournal.Open(path)
	if err != nil {
		return err
	}
	return journal.BootstrapResource(resource, 1, 1)
}

func main() {
	if os.Getenv("ELX_STAGE4_E2E_DISPOSABLE") != "1" || len(os.Args) != 8 {
		fmt.Fprintln(os.Stderr, "refusing non-disposable Stage 4 journal setup")
		os.Exit(2)
	}
	resource, err := uuid.Parse(os.Args[1])
	if err != nil || resource == uuid.Nil || resource.String() != os.Args[1] {
		fmt.Fprintln(os.Stderr, "invalid canonical resource")
		os.Exit(2)
	}
	if err = provision(resource.String(), os.Args[2], os.Args[3], os.Args[4]); err == nil {
		err = provision(resource.String(), os.Args[5], os.Args[6], os.Args[7])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("PASS: exact durable ElXray journals and store identities provisioned")
}
