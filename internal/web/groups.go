package web

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dzsec/cairn/internal/storage/sqlite"
)

func (a *App) handleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := a.groups.ListGroups(r.Context())
	if err != nil {
		a.log.Error("list groups", "err", err)
	}
	a.render(w, r, http.StatusOK, "groups.html", map[string]any{
		"Title":  "Groups",
		"Groups": groups,
		"Flash":  r.URL.Query().Get("flash"),
		"Error":  r.URL.Query().Get("error"),
	})
}

func (a *App) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/admin/groups?error="+url.QueryEscape("Group name is required."), http.StatusSeeOther)
		return
	}
	id, err := a.groups.CreateGroup(r.Context(), name, strings.TrimSpace(r.PostFormValue("description")))
	if err != nil {
		a.log.Error("create group", "name", name, "err", err)
		http.Redirect(w, r, "/admin/groups?error="+url.QueryEscape("Creating the group failed (duplicate name?)."), http.StatusSeeOther)
		return
	}
	a.log.Info("group created", "id", id, "name", name, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/groups/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func (a *App) handleGroupDetail(w http.ResponseWriter, r *http.Request) {
	g, ok := a.groupFromPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	members, err := a.groups.GroupDevices(ctx, g.ID)
	if err != nil {
		a.log.Error("group devices", "id", g.ID, "err", err)
	}
	assigned, err := a.groups.GroupProfiles(ctx, g.ID)
	if err != nil {
		a.log.Error("group profiles", "id", g.ID, "err", err)
	}

	// Options for the add-device / assign-profile selects: everything not
	// already in the group.
	allDevices, _ := a.devices.ListDevices(ctx)
	allProfiles, _ := a.profiles.ListProfiles(ctx)
	inGroup := map[string]bool{}
	for _, d := range members {
		inGroup[d.ID] = true
	}
	var addableDevices []sqlite.Device
	for _, d := range allDevices {
		if !inGroup[d.ID] {
			addableDevices = append(addableDevices, d)
		}
	}
	hasProfile := map[int64]bool{}
	for _, p := range assigned {
		hasProfile[p.ID] = true
	}
	var addableProfiles []sqlite.Profile
	for _, p := range allProfiles {
		if !hasProfile[p.ID] {
			addableProfiles = append(addableProfiles, p)
		}
	}

	a.render(w, r, http.StatusOK, "group.html", map[string]any{
		"Title":           g.Name,
		"Group":           g,
		"Members":         members,
		"Assigned":        assigned,
		"AddableDevices":  addableDevices,
		"AddableProfiles": addableProfiles,
		"Flash":           r.URL.Query().Get("flash"),
		"Error":           r.URL.Query().Get("error"),
	})
}

func (a *App) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	g, ok := a.groupFromPath(w, r)
	if !ok {
		return
	}
	if err := a.groups.DeleteGroup(r.Context(), g.ID); err != nil {
		a.log.Error("delete group", "id", g.ID, "err", err)
		http.Redirect(w, r, "/admin/groups?error="+url.QueryEscape("Deleting the group failed."), http.StatusSeeOther)
		return
	}
	a.log.Info("group deleted", "id", g.ID, "name", g.Name, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/groups?flash="+url.QueryEscape("Group deleted. Installed profiles stay on devices."), http.StatusSeeOther)
}

// handleGroupDeviceChange adds or removes a device (action=add|remove).
// Adding triggers a reconcile for that device.
func (a *App) handleGroupDeviceChange(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	g, ok := a.groupFromPath(w, r)
	if !ok {
		return
	}
	deviceID := r.PostFormValue("device_id")
	back := "/admin/groups/" + strconv.FormatInt(g.ID, 10)
	if deviceID == "" {
		http.Redirect(w, r, back+"?error="+url.QueryEscape("Choose a device."), http.StatusSeeOther)
		return
	}
	user := sessionFrom(r).Identity.Username
	switch r.PostFormValue("action") {
	case "remove":
		if err := a.groups.RemoveDeviceFromGroup(r.Context(), g.ID, deviceID); err != nil {
			a.log.Error("remove device from group", "group", g.ID, "device", deviceID, "err", err)
			http.Redirect(w, r, back+"?error="+url.QueryEscape("Removing the device failed."), http.StatusSeeOther)
			return
		}
		a.log.Info("group device removed", "group", g.ID, "device", deviceID, "user", user)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Device removed. Installed profiles stay until explicitly removed."), http.StatusSeeOther)
	default: // add
		if err := a.groups.AddDeviceToGroup(r.Context(), g.ID, deviceID); err != nil {
			a.log.Error("add device to group", "group", g.ID, "device", deviceID, "err", err)
			http.Redirect(w, r, back+"?error="+url.QueryEscape("Adding the device failed."), http.StatusSeeOther)
			return
		}
		a.log.Info("group device added", "group", g.ID, "device", deviceID, "user", user)
		a.reconcileDeviceAsync(deviceID)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Device added — assigned profiles are being pushed."), http.StatusSeeOther)
	}
}

// handleGroupProfileChange assigns or unassigns a profile (action=assign|unassign).
// Assigning triggers a reconcile for the whole group.
func (a *App) handleGroupProfileChange(w http.ResponseWriter, r *http.Request) {
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	g, ok := a.groupFromPath(w, r)
	if !ok {
		return
	}
	back := "/admin/groups/" + strconv.FormatInt(g.ID, 10)
	profileID, err := strconv.ParseInt(r.PostFormValue("profile_id"), 10, 64)
	if err != nil {
		http.Redirect(w, r, back+"?error="+url.QueryEscape("Choose a profile."), http.StatusSeeOther)
		return
	}
	user := sessionFrom(r).Identity.Username
	switch r.PostFormValue("action") {
	case "unassign":
		if err := a.groups.UnassignProfile(r.Context(), g.ID, profileID); err != nil {
			a.log.Error("unassign profile", "group", g.ID, "profile", profileID, "err", err)
			http.Redirect(w, r, back+"?error="+url.QueryEscape("Unassigning failed."), http.StatusSeeOther)
			return
		}
		a.log.Info("profile unassigned", "group", g.ID, "profile", profileID, "user", user)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Profile unassigned. Installed copies stay on devices."), http.StatusSeeOther)
	default: // assign
		if err := a.groups.AssignProfile(r.Context(), g.ID, profileID); err != nil {
			a.log.Error("assign profile", "group", g.ID, "profile", profileID, "err", err)
			http.Redirect(w, r, back+"?error="+url.QueryEscape("Assigning failed."), http.StatusSeeOther)
			return
		}
		a.log.Info("profile assigned", "group", g.ID, "profile", profileID, "user", user)
		a.reconcileGroupAsync(g.ID)
		http.Redirect(w, r, back+"?flash="+url.QueryEscape("Profile assigned — pushing to enrolled devices."), http.StatusSeeOther)
	}
}

// groupFromPath loads the {id} group or renders a 404.
func (a *App) groupFromPath(w http.ResponseWriter, r *http.Request) (sqlite.Group, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var g sqlite.Group
		g, err = a.groups.GetGroup(r.Context(), id)
		if err == nil {
			return g, true
		}
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, strconv.ErrSyntax) {
		a.log.Error("get group", "err", err)
	}
	a.render(w, r, http.StatusNotFound, "error.html", map[string]any{
		"Title": "Not found", "Message": "No such group.",
	})
	return sqlite.Group{}, false
}

// reconcileDeviceAsync runs a device reconcile off the request path (pushes can
// take APNs round-trips; the admin gets an immediate redirect instead).
func (a *App) reconcileDeviceAsync(deviceID string) {
	if a.rec == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := a.rec.ReconcileDevice(ctx, deviceID); err != nil {
			a.log.Warn("reconcile device failed", "device", deviceID, "err", err)
		}
	}()
}

func (a *App) reconcileGroupAsync(groupID int64) {
	if a.rec == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := a.rec.ReconcileGroup(ctx, groupID); err != nil {
			a.log.Warn("reconcile group failed", "group", groupID, "err", err)
		}
	}()
}
