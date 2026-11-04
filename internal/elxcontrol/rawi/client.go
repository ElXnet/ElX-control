// Package rawi implements the provider power operations used during fencing.
package rawi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const apiBase = "https://my.rawi.host/api/v1"

var serverID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

type Client struct {
	base  string
	token string
	http  *http.Client
}

func New(token string) (*Client, error) {
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("invalid RAWI token")
	}
	return &Client{
		base:  apiBase,
		token: token,
		http: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// RequestStop submits one hard power-off request. An error may mean the
// provider accepted it but the reply was lost. Check Power before retrying.
func (c *Client) RequestStop(ctx context.Context, id string) error {
	var result struct {
		Action string
		Queued bool
	}
	if err := c.request(ctx, http.MethodPost, id, "/power", `{"action":"stop"}`, http.StatusAccepted, &result); err != nil {
		return err
	}
	if result.Action != "stop" || !result.Queued {
		return errors.New("RAWI did not confirm a queued stop")
	}
	return nil
}

// Power reads the hypervisor status. The caller must treat all states other
// than exactly "stopped" as insufficient evidence to promote a replacement.
func (c *Client) Power(ctx context.Context, id string) (string, error) {
	var result struct {
		Status struct {
			Power string
		}
	}
	if err := c.request(ctx, http.MethodGet, id, "/status", "", http.StatusOK, &result); err != nil {
		return "", err
	}
	if result.Status.Power == "" {
		return "", errors.New("RAWI response lacks a power state")
	}
	return result.Status.Power, nil
}

// WaitStopped observes power-off after a stop request. It requires a deadline.
// It does not prevent a later restart or grant leadership.
func (c *Client) WaitStopped(ctx context.Context, id string, interval time.Duration) error {
	if _, ok := ctx.Deadline(); !ok || interval <= 0 {
		return errors.New("RAWI polling requires a deadline and positive interval")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		state, err := c.Power(ctx, id)
		if err != nil {
			return err
		}
		if state == "stopped" {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Client) request(ctx context.Context, method, id, path, body string, expected int, out any) error {
	if !serverID.MatchString(id) {
		return errors.New("invalid RAWI server ID")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/servers/"+id+path, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("RAWI %s request failed: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != expected {
		return fmt.Errorf("RAWI %s returned HTTP %d", path, resp.StatusCode)
	}
	const maxBody = 32 * 1024
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("read RAWI %s response: %w", path, err)
	}
	if len(data) > maxBody || json.Unmarshal(data, out) != nil {
		return fmt.Errorf("invalid RAWI %s response", path)
	}
	return nil
}
