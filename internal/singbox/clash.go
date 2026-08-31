package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ClashConnection is one online connection from sing-box's clash API.
type ClashConnection struct {
	ID       string `json:"id"`
	Metadata struct {
		User     string `json:"user"`
		SourceIP string `json:"sourceIP"`
	} `json:"metadata"`
	Start    time.Time `json:"start"`
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
}

type clashConnectionsResponse struct {
	Connections []ClashConnection `json:"connections"`
}

// FetchOnlineConnections queries the sing-box clash API /connections endpoint
// and returns the connections that are online right now. It returns an empty
// slice (no error) when sing-box is not reachable, so callers degrade to
// "nobody online" instead of failing the panel request.
func FetchOnlineConnections(ctx context.Context, clashAddr string) ([]ClashConnection, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+clashAddr+"/connections", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clash api unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clash api status %d", resp.StatusCode)
	}
	var out clashConnectionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("clash api decode: %w", err)
	}
	return out.Connections, nil
}

// CloseConnections terminates the given active connections by id via the
// sing-box clash API DELETE /connections/:id endpoint. Missing/unknown ids are
// ignored (the connection may already be gone). Returns the number of ids that
// were successfully closed.
func CloseConnections(ctx context.Context, clashAddr string, ids []string) (int, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	closed := 0
	for _, id := range ids {
		if id == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://"+clashAddr+"/connections/"+id, nil)
		if err != nil {
			return closed, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return closed, fmt.Errorf("clash api unavailable: %w", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
			closed++
		}
	}
	return closed, nil
}
