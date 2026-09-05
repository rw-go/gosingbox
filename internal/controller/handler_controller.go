package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/transpiler"
)

// Handler handles /node/handler/* routes. User add/remove mutate the desired
// user set and trigger a debounced sing-box restart (no HandlerService).
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

	var username string
	if len(req.Data) > 0 {
		username = req.Data[0].User
	}

	// On UUID rotation (prevVlessUuid present) the panel swaps a user's VLESS
	// key: drop the old user and (below) terminate its live connections so the
	// client re-auths with the new key. Mirrors official node 3.4.1 addUser.
	if req.HashData.PrevVlessUID != "" {
		h.app.RemoveUser(req.HashData.PrevVlessUID)
	}

	for _, item := range req.Data {
		switch item.Type {
		case "vless":
			uuid := firstNonEmpty(item.UUID, req.HashData.VlessUUID)
			if uuid == "" {
				continue
			}
			h.app.AddUser(transpiler.VlessUser{Name: firstNonEmpty(item.User, uuid), UUID: uuid, Flow: item.Flow})
		case "shadowsocks22":
			if item.Password == "" {
				continue
			}
			name := firstNonEmpty(item.User, item.Password)
			h.app.AddSsUser(transpiler.SsUser{Name: name, Password: item.Password})
		}
	}

	if req.HashData.PrevVlessUID != "" && username != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := h.app.DropUsers(ctx, []string{username}); err != nil {
			h.log.Debug("add-user: drop previous connections failed", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
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
			switch ib.Type {
			case "vless":
				if u.UserData.VlessUUID == "" {
					continue
				}
				h.app.AddUser(transpiler.VlessUser{
					Name: firstNonEmpty(u.UserData.UserID, u.UserData.VlessUUID),
					UUID: u.UserData.VlessUUID,
					Flow: ib.Flow,
				})
			case "shadowsocks22":
				if u.UserData.SSPassword == "" {
					continue
				}
				h.app.AddSsUser(transpiler.SsUser{
					Name:     u.UserData.UserID,
					Password: base64.StdEncoding.EncodeToString([]byte(u.UserData.SSPassword)),
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
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
	h.app.RemoveUser(req.HashData.VlessUUID)
	h.app.RemoveSsUser(req.Username)

	// Immediately terminate live connections for the removed user, aligning with
	// official node 3.4.1 DropConnectionsEvent on user removal.
	if req.Username != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := h.app.DropUsers(ctx, []string{req.Username}); err != nil {
			h.log.Debug("remove-user: drop connections failed", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
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
	dropUserNames := make([]string, 0, len(req.Users))
	for _, u := range req.Users {
		h.app.RemoveUser(u.HashUUID)
		h.app.RemoveSsUser(u.UserID)
		if u.UserID != "" {
			dropUserNames = append(dropUserNames, u.UserID)
		}
	}

	// Immediately terminate live connections for all removed users, aligning with
	// official node 3.4.1 DropConnectionsEvent on user removal.
	if len(dropUserNames) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := h.app.DropUsers(ctx, dropUserNames); err != nil {
			h.log.Debug("remove-users: drop connections failed", "error", err)
		}
	}

	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
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
