package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
)

// Handler applies complete user authorization sets synchronously by inbound tag.
type Handler struct {
	app *app.App
	log *slog.Logger
}

func NewHandler(a *app.App, log *slog.Logger) *Handler {
	return &Handler{app: a, log: log}
}

// Router mounts /node/handler/* sub-paths.
func (h *Handler) Router(mux *http.ServeMux) {
	mux.HandleFunc("/node/handler/add-user", h.addUser)
	mux.HandleFunc("/node/handler/add-users", h.addUsers)
	mux.HandleFunc("/node/handler/remove-user", h.removeUser)
	mux.HandleFunc("/node/handler/remove-users", h.removeUsers)
	mux.HandleFunc("/node/handler/drop-users-connections", h.dropUsersConnections)
	mux.HandleFunc("/node/handler/drop-ips", h.dropIPs)
}

type vlessUserItem struct {
	Type     string `json:"type"`
	Tag      string `json:"tag"`
	User     string `json:"username"`
	UUID     string `json:"uuid"`
	Flow     string `json:"flow"`
	Password string `json:"password"`
}

type addUserRequest struct {
	Data     []vlessUserItem `json:"data"`
	HashData struct {
		VlessUUID    string `json:"vlessUuid"`
		PrevVlessUID string `json:"prevVlessUuid"`
	} `json:"hashData"`
}

type addUsersRequest struct {
	AffectedInboundTags []string `json:"affectedInboundTags"`
	Users               []struct {
		InboundData []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
			Flow string `json:"flow"`
		} `json:"inboundData"`
		UserData struct {
			UserID     string `json:"userId"`
			HashUUID   string `json:"hashUuid"`
			VlessUUID  string `json:"vlessUuid"`
			SSPassword string `json:"ssPassword"`
		} `json:"userData"`
	} `json:"users"`
}

type removeUserRequest struct {
	Username string `json:"username"`
	HashData struct {
		VlessUUID string `json:"vlessUuid"`
	} `json:"hashData"`
}

type removeUsersRequest struct {
	Users []struct {
		UserID   string `json:"userId"`
		HashUUID string `json:"hashUuid"`
	} `json:"users"`
}

func (h *Handler) addUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var req addUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}

	// Reject the whole request before UUID rotation or any user mutation.
	for _, item := range req.Data {
		if h.rejectUnsupportedProtocol(w, item.Type) {
			return
		}
	}
	update := state.Update{HashUUID: req.HashData.VlessUUID, PreviousUUID: req.HashData.PrevVlessUID}
	for _, item := range req.Data {
		if update.ID == "" {
			update.ID = item.User
		}
		credential := item.Password
		flow := ""
		if item.Type == "vless" {
			credential = firstNonEmpty(item.UUID, req.HashData.VlessUUID)
			flow = item.Flow
		}
		update.Memberships = append(update.Memberships, state.Membership{Tag: item.Tag, Protocol: item.Type, User: state.User{ID: item.User, Credential: credential, Flow: flow}})
	}
	h.writeUserResult(w, h.app.UpdateUsers([]state.Update{update}))
}

func (h *Handler) addUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var req addUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	for _, u := range req.Users {
		for _, ib := range u.InboundData {
			if h.rejectUnsupportedProtocol(w, ib.Type) {
				return
			}
		}
	}
	updates := make([]state.Update, 0, len(req.Users))
	for _, u := range req.Users {
		update := state.Update{ID: u.UserData.UserID, HashUUID: u.UserData.VlessUUID, PreviousUUID: u.UserData.HashUUID}
		for _, ib := range u.InboundData {
			credential := u.UserData.VlessUUID
			flow := ""
			if ib.Type == "vless" {
				flow = ib.Flow
			}
			if ib.Type == "shadowsocks22" {
				credential = base64.StdEncoding.EncodeToString([]byte(u.UserData.SSPassword))
			}
			update.Memberships = append(update.Memberships, state.Membership{Tag: ib.Tag, Protocol: ib.Type, User: state.User{ID: u.UserData.UserID, Credential: credential, Flow: flow}})
		}
		updates = append(updates, update)
	}
	h.writeUserResult(w, h.app.UpdateUsers(updates))
}

func (h *Handler) writeUserResult(w http.ResponseWriter, err error) {
	var message any
	if err != nil {
		message = err.Error()
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": err == nil, "error": message}})
}

func (h *Handler) rejectUnsupportedProtocol(w http.ResponseWriter, protocol string) bool {
	// The AnyTLS handler also remains testable in builds without management APIs.
	if protocol == "anytls" || contract.CurrentCapabilities().Manages(protocol) {
		return false
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{
		"success": false,
		"error":   fmt.Sprintf("unsupported user protocol: %q", protocol),
	}})
	return true
}

func (h *Handler) removeUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var req removeUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	h.writeUserResult(w, h.app.UpdateUsers([]state.Update{{ID: req.Username, HashUUID: req.HashData.VlessUUID}}))
}

func (h *Handler) removeUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var req removeUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	updates := make([]state.Update, 0, len(req.Users))
	for _, u := range req.Users {
		updates = append(updates, state.Update{ID: u.UserID, HashUUID: u.HashUUID})
	}
	h.writeUserResult(w, h.app.UpdateUsers(updates))
}

func (h *Handler) dropUsersConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var body struct {
		UserIDs []string `json:"userIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.UserIDs) == 0 {
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": false, "error": nil}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err := h.app.DropUsers(ctx, body.UserIDs); err != nil {
		h.log.Warn("drop users connections failed", "error", err)
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
}

func (h *Handler) dropIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.IPs) == 0 {
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": false, "error": nil}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if _, err := h.app.DropIPs(ctx, body.IPs); err != nil {
		h.log.Warn("drop ips failed", "error", err)
		writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
