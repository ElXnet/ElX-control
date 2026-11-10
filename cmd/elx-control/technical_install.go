package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
)

// enqueueTechnicalInstall is an operator-only technical workflow. It accepts
// no untrusted subscription selector or signing key: exact scope comes from
// the protected, current Control binding manifest. The PostgreSQL ledger
// atomically verifies the PREPARED profile, purchased rights and policy CAS.
// The queued INSTALL alone cannot grant any VPN payload or device slot.
func enqueueTechnicalInstall(ctx context.Context, db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("enqueue-technical-install", flag.ContinueOnError)
	node := fs.String("node", "", "Control-pinned node UUID")
	resource := fs.String("resource", "", "Control-pinned resource UUID")
	profile := fs.String("profile", "", "already prepared technical VLESS profile UUID")
	operation := fs.String("operation", "", "distinct idempotent INSTALL operation UUID")
	entitlement := fs.String("entitlement", "", "purchased entitlement UUID")
	email := fs.String("email", "", "existing prepared VLESS technical email")
	inboundTag := fs.String("inbound", "", "existing prepared VLESS inbound tag")
	flow := fs.String("flow", "", "signed VLESS flow: empty or xtls-rprx-vision")
	revision := fs.Uint64("core-revision", 0, "committed ElXray policy revision")
	notBefore := fs.Int64("not-before", 0, "short-lived signed operation start, UTC Unix")
	notAfter := fs.Int64("not-after", 0, "short-lived signed operation expiry, UTC Unix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *revision == 0 || *notBefore <= 0 ||
		*notAfter <= *notBefore || *notAfter-*notBefore > 60 ||
		(*flow != "" && *flow != "xtls-rprx-vision") {
		return errors.New("invalid signed INSTALL revision, flow or 60-second validity window")
	}
	profileID, e1 := uuid.Parse(*profile)
	operationID, e2 := uuid.Parse(*operation)
	entitlementID, e3 := uuid.Parse(*entitlement)
	if e1 != nil || e2 != nil || e3 != nil ||
		profileID == uuid.Nil || operationID == uuid.Nil || entitlementID == uuid.Nil ||
		profileID.String() != *profile || operationID.String() != *operation ||
		entitlementID.String() != *entitlement {
		return errors.New("canonical non-zero profile, operation and entitlement UUIDs are required")
	}
	bindings, err := loadBindings()
	if err != nil {
		return fmt.Errorf("trusted technical INSTALL manifest unavailable: %w", err)
	}
	for _, binding := range bindings {
		if binding.Target.NodeID != *node || binding.Target.ResourceID != *resource {
			continue
		}
		if binding.ExecutorID == "" || binding.Epoch <= 0 {
			return errors.New("technical INSTALL requires executor-bound Control authority")
		}
		g := corepolicy.ProfileGrantIntent{
			Version: 2, Action: "install",
			OperationID: operationID, ProfileID: profileID,
			NodeID: uuid.MustParse(binding.Target.NodeID),
			ResourceID: uuid.MustParse(binding.Target.ResourceID),
			ExecutorID: uuid.MustParse(binding.ExecutorID),
			SubscriptionID: binding.Subscription, Email: *email,
			InboundTag: *inboundTag, Flow: *flow, ProfileGeneration: 1,
			AuthorityGeneration: uint64(binding.Epoch),
			PolicyRevision: *revision, NotBefore: *notBefore, NotAfter: *notAfter,
		}
		queued, err := journal.QueueTechnicalInstall(ctx, db, journal.InstallReservation{
			Grant: g, EntitlementID: entitlementID.String(),
			PinnedSubscription: binding.Subscription,
		})
		if err != nil {
			return err
		}
		fmt.Printf("technical VLESS INSTALL %s operation=%s profile=%s (payload NOT admitted)\n",
			queued.State, queued.OperationID, queued.ProfileID)
		return nil
	}
	return errors.New("node/resource not present in current protected Control manifest")
}
