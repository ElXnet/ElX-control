// Package management exposes a deliberately small privileged Unix-socket API.
// A public subscription URL must never grant access to this API.
package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
)

var ErrNotFound = errors.New("management resource not found")

type Entitlement struct {
	ID string `json:"id"`
	ActiveSlots int `json:"activeSlots"`
	ValidUntil time.Time `json:"validUntil"`
	Enabled bool `json:"enabled"`
	Devices int64 `json:"devices"`
	Occupied int64 `json:"occupied"`
}

type Page struct {
	Items []Entitlement `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type Device struct {
	ID string `json:"id"`
	KeyGeneration int64 `json:"keyGeneration"`
	Revoked bool `json:"revoked"`
}

type Session struct {
	ID string `json:"id"`
	DeviceID string `json:"deviceId"`
	NodeID string `json:"nodeId"`
	ProfileID string `json:"profileId,omitempty"`
	Generation int64 `json:"generation"`
	State string `json:"state"`
	ReservedAt time.Time `json:"reservedAt"`
}

type RateBudget struct {
	Up int64 `json:"up"`
	Down int64 `json:"down"`
}

type Grant struct {
	NodeID string `json:"nodeId"`
	ResourceID string `json:"resourceId"`
	Up int64 `json:"up"`
	Down int64 `json:"down"`
	Epoch int64 `json:"epoch"`
	Pending bool `json:"pending"`
}

type Period struct {
	ID string `json:"id"`
	StartsAt time.Time `json:"startsAt"`
	EndsAt time.Time `json:"endsAt"`
	Direction string `json:"direction"`
	Threshold int64 `json:"thresholdBytes"`
	UpBytes int64 `json:"upBytes"`
	DownBytes int64 `json:"downBytes"`
	ReducedUp int64 `json:"reducedUp"`
	ReducedDown int64 `json:"reducedDown"`
	FUPActive bool `json:"fupActive"`
	Cadence string `json:"cadence,omitempty"`
	Timezone string `json:"timezone,omitempty"`
}

type Detail struct {
	Entitlement Entitlement `json:"entitlement"`
	Devices []Device `json:"devices"`
	Sessions []Session `json:"sessions"`
	SessionsTruncated bool `json:"sessionsTruncated"`
	RateBudget *RateBudget `json:"rateBudget"`
	Grants []Grant `json:"grants"`
	Periods []Period `json:"periods"`
}

type ReconcileResult struct {
	EntitlementID string `json:"entitlementId"`
	Active bool `json:"active"`
	Queued int `json:"queued"`
	Pending int `json:"pending"`
	Unchanged int `json:"unchanged"`
}

type Store interface {
	List(context.Context, string, int) (Page, error)
	Get(context.Context, string) (Detail, error)
	QueueDrain(context.Context, string, string) error
	Reconcile(context.Context, string) (ReconcileResult, error)
}

type SQLStore struct { DB *sql.DB }

const maxPageSize = 100

func canonical(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func readEntitlement(row interface{ Scan(...any) error }) (Entitlement, error) {
	var e Entitlement
	err := row.Scan(&e.ID, &e.ActiveSlots, &e.ValidUntil, &e.Enabled, &e.Devices, &e.Occupied)
	return e, err
}

const entitlementColumns = "SELECT e.id::text,e.active_slots,e.valid_until,e.enabled," +
	"(SELECT count(*) FROM elx_devices d WHERE d.entitlement_id=e.id)," +
	"(SELECT count(*) FROM elx_session_owners o WHERE o.entitlement_id=e.id AND o.state<>'released') " +
	"FROM elx_entitlements e "

func (s SQLStore) List(ctx context.Context, after string, limit int) (Page, error) {
	out := Page{Items: []Entitlement{}}
	if s.DB == nil || limit < 1 || limit > maxPageSize || (after != "" && !canonical(after)) {
		return out, journal.ErrInvalid
	}
	var cursor any
	if after != "" { cursor = after }
	rows, err := s.DB.QueryContext(ctx, entitlementColumns +
		"WHERE ($1::uuid IS NULL OR e.id>$1::uuid) ORDER BY e.id LIMIT $2", cursor, limit+1)
	if err != nil { return out, err }
	defer rows.Close()
	for rows.Next() {
		item, err := readEntitlement(rows)
		if err != nil { return out, err }
		out.Items = append(out.Items, item)
	}
	if err := rows.Err(); err != nil { return out, err }
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.NextCursor = out.Items[len(out.Items)-1].ID
	}
	return out, nil
}

func (s SQLStore) Get(ctx context.Context, id string) (Detail, error) {
	out := Detail{Devices: []Device{}, Sessions: []Session{}, Grants: []Grant{}, Periods: []Period{}}
	if s.DB == nil || !canonical(id) { return out, journal.ErrInvalid }
	e, err := readEntitlement(s.DB.QueryRowContext(ctx, entitlementColumns + "WHERE e.id=$1", id))
	if errors.Is(err, sql.ErrNoRows) { return out, ErrNotFound }
	if err != nil { return out, err }
	out.Entitlement = e

	rows, err := s.DB.QueryContext(ctx, "SELECT id::text,key_generation,revoked FROM elx_devices WHERE entitlement_id=$1 ORDER BY id LIMIT 1001", id)
	if err != nil { return out, err }
	for rows.Next() {
		var v Device
		if err := rows.Scan(&v.ID, &v.KeyGeneration, &v.Revoked); err != nil { rows.Close(); return out, err }
		out.Devices = append(out.Devices, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil { return out, err }
	if len(out.Devices) > 1000 { return out, errors.New("device listing exceeds management safety bound") }

	rows, err = s.DB.QueryContext(ctx, "SELECT id::text,device_id::text,node_id::text,COALESCE(profile_id::text,''),generation,state,reserved_at FROM elx_session_owners WHERE entitlement_id=$1 ORDER BY reserved_at DESC,id LIMIT 201", id)
	if err != nil { return out, err }
	for rows.Next() {
		var v Session
		if err := rows.Scan(&v.ID,&v.DeviceID,&v.NodeID,&v.ProfileID,&v.Generation,&v.State,&v.ReservedAt); err != nil { rows.Close(); return out, err }
		out.Sessions = append(out.Sessions,v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil { return out, err }
	if len(out.Sessions)>200 { out.Sessions=out.Sessions[:200]; out.SessionsTruncated=true }

	var budget RateBudget
	err = s.DB.QueryRowContext(ctx, "SELECT up_limit,down_limit FROM elx_rate_budgets WHERE entitlement_id=$1", id).Scan(&budget.Up,&budget.Down)
	switch {
	case err == nil: out.RateBudget=&budget
	case errors.Is(err,sql.ErrNoRows):
	default: return out,err
	}

	rows,err = s.DB.QueryContext(ctx, "SELECT g.node_id::text,g.resource_id::text,g.committed_up,g.committed_down,g.epoch,EXISTS(SELECT 1 FROM elx_rate_moves m WHERE m.node_id=g.node_id AND m.resource_id=g.resource_id AND NOT m.finalized) FROM elx_rate_grants g WHERE g.entitlement_id=$1 ORDER BY g.node_id,g.resource_id LIMIT 1001",id)
	if err != nil { return out,err }
	for rows.Next(){
		var v Grant
		if err:=rows.Scan(&v.NodeID,&v.ResourceID,&v.Up,&v.Down,&v.Epoch,&v.Pending);err!=nil{rows.Close();return out,err}
		out.Grants=append(out.Grants,v)
	}
	err=rows.Err();rows.Close()
	if err!=nil{return out,err}
	if len(out.Grants)>1000{return out,errors.New("grant listing exceeds management safety bound")}

	rows,err=s.DB.QueryContext(ctx, "SELECT p.id::text,p.starts_at,p.ends_at,p.direction,p.threshold_bytes,p.up_bytes,p.down_bytes,p.reduced_up,p.reduced_down,(f.period_id IS NOT NULL),COALESCE(s.cadence,''),COALESCE(s.timezone_name,'') FROM elx_usage_periods p LEFT JOIN elx_fup_events f ON f.period_id=p.id LEFT JOIN elx_period_schedules s ON s.id=p.schedule_id WHERE p.entitlement_id=$1 ORDER BY p.starts_at DESC,p.id LIMIT 101",id)
	if err!=nil{return out,err}
	for rows.Next(){
		var v Period
		if err:=rows.Scan(&v.ID,&v.StartsAt,&v.EndsAt,&v.Direction,&v.Threshold,&v.UpBytes,&v.DownBytes,&v.ReducedUp,&v.ReducedDown,&v.FUPActive,&v.Cadence,&v.Timezone);err!=nil{rows.Close();return out,err}
		out.Periods=append(out.Periods,v)
	}
	err=rows.Err();rows.Close()
	if err!=nil{return out,err}
	if len(out.Periods)>100{return out,errors.New("period listing exceeds management safety bound")}
	return out,nil
}

func (s SQLStore) QueueDrain(ctx context.Context, entitlement, owner string) error {
	if s.DB==nil || !canonical(entitlement) || !canonical(owner) { return journal.ErrInvalid }
	// The selector is server-authoritative; callers cannot authorize an owner
	// belonging to another entitlement by choosing an arbitrary UUID.
	var match bool
	if err:=s.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM elx_session_owners WHERE id=$1 AND entitlement_id=$2)", owner,entitlement).Scan(&match);err!=nil{return err}
	if !match{return ErrNotFound}
	id,_:=uuid.Parse(owner)
	return session.QueueDrain(ctx,s.DB,id)
}

func (s SQLStore) Reconcile(ctx context.Context, id string) (ReconcileResult,error) {
	out:=ReconcileResult{}
	if s.DB==nil || !canonical(id){return out,journal.ErrInvalid}
	r,err:=journal.ReconcileFUP(ctx,s.DB,id)
	if err!=nil{return out,err}
	return ReconcileResult{EntitlementID:r.EntitlementID,Active:r.Active,Queued:r.Queued,Pending:r.Pending,Unchanged:r.Unchanged},nil
}

// Handler has no network listener. Its caller must bind a local Unix socket
// with restrictive filesystem permissions, never a public TCP address.
func Handler(store Store) http.Handler {
	mux:=http.NewServeMux()
	mux.HandleFunc("GET /v1/entitlements",func(w http.ResponseWriter,r *http.Request){
		limit:=50
		if raw:=r.URL.Query().Get("limit");raw!=""{
			v,err:=strconv.Atoi(raw)
			if err!=nil || v<1 || v>maxPageSize{writeErr(w,http.StatusBadRequest);return}
			limit=v
		}
		after:=r.URL.Query().Get("after")
		if after!="" && !canonical(after){writeErr(w,http.StatusBadRequest);return}
		data,err:=store.List(r.Context(),after,limit)
		writeResult(w,data,err)
	})
	mux.HandleFunc("GET /v1/entitlements/{id}",func(w http.ResponseWriter,r *http.Request){
		if !canonical(r.PathValue("id")){writeErr(w,http.StatusBadRequest);return}
		data,err:=store.Get(r.Context(),r.PathValue("id"))
		writeResult(w,data,err)
	})
	mux.HandleFunc("POST /v1/entitlements/{id}/sessions/{owner}/drain",func(w http.ResponseWriter,r *http.Request){
		id,owner:=r.PathValue("id"),r.PathValue("owner")
		if !canonical(id)||!canonical(owner){writeErr(w,http.StatusBadRequest);return}
		if err:=store.QueueDrain(r.Context(),id,owner);err!=nil{writeErr(w,errorStatus(err));return}
		// The slot is NOT released here. A signed core fence is still required.
		writeJSON(w,http.StatusAccepted,map[string]string{"state":"draining","release":"pending-signed-core-fence"})
	})
	mux.HandleFunc("POST /v1/entitlements/{id}/reconcile-fup",func(w http.ResponseWriter,r *http.Request){
		id:=r.PathValue("id")
		if !canonical(id){writeErr(w,http.StatusBadRequest);return}
		data,err:=store.Reconcile(r.Context(),id)
		writeResult(w,data,err)
	})
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		w.Header().Set("Cache-Control","no-store")
		if strings.HasPrefix(r.URL.Path,"/v1/"){mux.ServeHTTP(w,r);return}
		writeErr(w,http.StatusNotFound)
	})
}

func errorStatus(err error) int {
	switch {
	case errors.Is(err,ErrNotFound), errors.Is(err,sql.ErrNoRows):return http.StatusNotFound
	case errors.Is(err,journal.ErrInvalid):return http.StatusBadRequest
	case errors.Is(err,session.ErrDrain):return http.StatusConflict
	default:return http.StatusServiceUnavailable
	}
}

func writeResult(w http.ResponseWriter,data any,err error){
	if err!=nil {writeErr(w,errorStatus(err));return}
	writeJSON(w,http.StatusOK,data)
}
func writeErr(w http.ResponseWriter,status int){writeJSON(w,status,map[string]string{"error":http.StatusText(status)})}
func writeJSON(w http.ResponseWriter,status int,data any){
	w.Header().Set("Content-Type","application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
