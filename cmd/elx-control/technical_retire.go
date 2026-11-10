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

// enqueueTechnicalRetire is an operator-only, independently signed v2
// revocation. PostgreSQL verifies the existing technical identity, authority,
// generation, executor and effective VLESS flow before reserving its intent.
// Revocation itself does not free any session owner or bandwidth allocation.
func enqueueTechnicalRetire(ctx context.Context, db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("enqueue-technical-retire", flag.ContinueOnError)
	node := fs.String("node", "", "Control-pinned node UUID")
	resource := fs.String("resource", "", "Control-pinned resource UUID")
	profile := fs.String("profile", "", "existing technical VLESS profile UUID")
	operation := fs.String("operation", "", "distinct retire operation UUID")
	entitlement := fs.String("entitlement", "", "original entitlement UUID (may be expired)")
	email := fs.String("email", "", "existing technical VLESS email")
	inboundTag := fs.String("inbound", "", "existing VLESS inbound tag")
	flow := fs.String("flow", "", "original signed VLESS flow")
	revision := fs.Uint64("core-revision", 0, "Control-pinned current policy revision")
	notBefore := fs.Int64("not-before", 0, "stable UTC Unix start")
	notAfter := fs.Int64("not-after", 0, "stable UTC Unix expiry <=60 seconds")
	if err := fs.Parse(args); err != nil { return err }
	if fs.NArg() != 0 || *revision == 0 || *notBefore <= 0 ||
		*notAfter <= *notBefore || *notAfter-*notBefore > 60 ||
		(*flow != "" && *flow != "xtls-rprx-vision") {
		return errors.New("explicit valid v2 RETIRE flow and revision are required")
	}
	profileID, e1 := uuid.Parse(*profile)
	opID, e2 := uuid.Parse(*operation)
	entID, e3 := uuid.Parse(*entitlement)
	if e1 != nil || e2 != nil || e3 != nil || profileID == uuid.Nil ||
		opID == uuid.Nil || entID == uuid.Nil ||
		profileID.String() != *profile || opID.String() != *operation ||
		entID.String() != *entitlement {
		return errors.New("canonical non-zero technical RETIRE identifiers are required")
	}
	bindings, err := loadBindings()
	if err != nil { return fmt.Errorf("trusted Control binding unavailable: %w", err) }
	for _, b := range bindings {
		if b.Target.NodeID != *node || b.Target.ResourceID != *resource { continue }
		if b.ExecutorID == "" || b.Epoch <= 0 {
			return errors.New("RETIRE requires pinned Control executor/authority generation")
		}
		g := corepolicy.ProfileGrantIntent{
			Version: 2, Action: "retire", OperationID: opID,
			NodeID: uuid.MustParse(b.Target.NodeID),
			ResourceID: uuid.MustParse(b.Target.ResourceID),
			ExecutorID: uuid.MustParse(b.ExecutorID),
			ProfileID: profileID, SubscriptionID: b.Subscription,
			Email: *email, InboundTag: *inboundTag, Flow: *flow,
			ProfileGeneration: 2, AuthorityGeneration: uint64(b.Epoch),
			PolicyRevision: *revision, NotBefore: *notBefore, NotAfter: *notAfter,
		}
		result, err := journal.QueueTechnicalRetire(ctx, db, journal.RetireReservation{
			Grant: g, EntitlementID: entID.String(), PinnedSubscription: b.Subscription,
		})
		if err != nil { return err }
		fmt.Printf("technical VLESS RETIRE %s operation=%s profile=%s (no owner release)\n",
			result.State, result.OperationID, result.ProfileID)
		return nil
	}
	return errors.New("RETIRE target not present in protected Control manifest")
}
