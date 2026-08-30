package controller

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/rwsbnode/gosingbox/internal/app"
	"github.com/rwsbnode/gosingbox/internal/transpiler"
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
	mux.HandleFunc("/node/handler/get-inbound-users", h.getInboundUsers)
	mux.HandleFunc("/node/handler/get-inbound-users-count", h.getInboundUsersCount)
	mux.HandleFunc("/node/handler/drop-users-connections", h.dropUsersConnections)
	mux.HandleFunc("/node/handler/drop-ips", h.dropIPs)
}

type vlessUserItem struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
	User string `json:"username"`
	UUID string `json:"uuid"`
	Flow string `json:"flow"`
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
			UserID    string `json:"userId"`
			HashUUID  string `json:"hashUuid"`
			VlessUUID string `json:"vlessUuid"`
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
	var req addUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	for _, item := range req.Data {
		if item.Type != "vless" {
			continue
		}
		uuid := firstNonEmpty(item.UUID, req.HashData.VlessUUID)
		if uuid == "" {
			continue
		}
		h.app.AddUser(transpiler.VlessUser{Name: firstNonEmpty(item.User, uuid), UUID: uuid, Flow: item.Flow})
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
}

func (h *Handler) addUsers(w http.ResponseWriter, r *http.Request) {
	var req addUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	for _, u := range req.Users {
		for _, ib := range u.InboundData {
			if ib.Type != "vless" {
				continue
			}
			h.app.AddUser(transpiler.VlessUser{
				Name: firstNonEmpty(u.UserData.UserID, u.UserData.VlessUUID),
				UUID: u.UserData.VlessUUID,
				Flow: ib.Flow,
			})
		}
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
}

func (h *Handler) removeUser(w http.ResponseWriter, r *http.Request) {
	var req removeUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	h.app.RemoveUser(req.HashData.VlessUUID)
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
}

func (h *Handler) removeUsers(w http.ResponseWriter, r *http.Request) {
	var req removeUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, envelope{Response: map[string]any{"success": false, "error": err.Error()}})
		return
	}
	for _, u := range req.Users {
		h.app.RemoveUser(u.HashUUID)
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
}

func (h *Handler) getInboundUsersCount(w http.ResponseWriter, r *http.Request) {
	users := h.app.CurrentUsers()
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"count": len(users)}})
}

func (h *Handler) getInboundUsers(w http.ResponseWriter, r *http.Request) {
	users := h.app.CurrentUsers()
	list := []any{}
	for _, u := range users {
		list = append(list, map[string]any{"username": u, "level": 0})
	}
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"users": list}})
}

func (h *Handler) dropUsersConnections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{Response: map[string]any{"success": true, "error": nil}})
}

func (h *Handler) dropIPs(w http.ResponseWriter, r *http.Request) {
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
