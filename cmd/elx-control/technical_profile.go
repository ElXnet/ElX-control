package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
)

// enqueueTechnicalProfile is a privileged, *non-admitting* preparatory command.
// It only writes Control's authoritative operation INTENT: it cannot create
// an active Xray user, a session owner or a billable slot by itself.
func enqueueTechnicalProfile(ctx context.Context, db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("enqueue-technical-profile", flag.ContinueOnError)
	node := fs.String("node", "", "Control-pinned node UUID")
	resource := fs.String("resource", "", "Control-pinned resource UUID")
	profile := fs.String("profile", "", "new stable technical VLESS profile UUID")
	operation := fs.String("operation", "", "idempotency operation UUID")
	entitlement := fs.String("entitlement", "", "purchased entitlement UUID")
	email := fs.String("email", "", "unique VLESS technical email")
	inboundTag := fs.String("inbound", "", "existing VLESS inbound tag")
	revision := fs.Uint64("core-revision", 0, "known committed ElXray policy revision")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *revision == 0 {
		return errors.New("explicit committed core revision required for technical preparation")
	}
	profileID, e1 := uuid.Parse(*profile)
	opID, e2 := uuid.Parse(*operation)
	entID, e3 := uuid.Parse(*entitlement)
	if e1 != nil || e2 != nil || e3 != nil ||
		profileID == uuid.Nil || opID == uuid.Nil || entID == uuid.Nil ||
		profileID.String() != *profile || opID.String() != *operation ||
		entID.String() != *entitlement {
		return errors.New("canonical non-zero profile, operation and entitlement UUIDs required")
	}
	bindings, err := loadBindings()
	if err != nil {
		return fmt.Errorf("current trusted Control binding unavailable: %w", err)
	}
	var selected *struct {
		node, resource, executor, subscription string
		epoch int64
	}
	for _, b := range bindings {
		if *node == b.Target.NodeID && *resource == b.Target.ResourceID {
			if b.ExecutorID == "" || b.Epoch <= 0 {
				return errors.New("technical provisioning requires v3 executor-bound Control grant")
			}
			selected = &struct {
				node, resource, executor, subscription string
				epoch int64
			}{b.Target.NodeID, b.Target.ResourceID, b.ExecutorID, b.Subscription, b.Epoch}
			break
		}
	}
	if selected == nil {
		return errors.New("node/resource not present in protected Control manifest")
	}
	now := time.Now().UTC().Unix()
	grant := corepolicy.ProfileGrantIntent{
		Version: 1, Action: "prepare", OperationID: opID,
		NodeID: uuid.MustParse(selected.node), ResourceID: uuid.MustParse(selected.resource),
		ExecutorID: uuid.MustParse(selected.executor), ProfileID: profileID,
		SubscriptionID: selected.subscription, Email: *email, InboundTag: *inboundTag,
		ProfileGeneration: 1, AuthorityGeneration: uint64(selected.epoch),
		PolicyRevision: *revision, NotBefore: now, NotAfter: now + 45,
	}
	receipt, err := journal.QueueTechnicalProfile(ctx, db, journal.ProfileReservation{
		Grant: grant, EntitlementID: entID.String(),
		PinnedSubscription: selected.subscription,
	})
	if err != nil {
		return err
	}
	fmt.Printf("technical VLESS preparation %s operation=%s profile=%s (payload NOT admitted)\n",
		receipt.State, receipt.OperationID, receipt.ProfileID)
	return nil
}
