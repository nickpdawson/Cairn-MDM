package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dzsec/cairn/internal/ca"
	"github.com/dzsec/cairn/internal/profile"
	"github.com/dzsec/cairn/internal/storage/sqlite"
)

func (a *App) handleBuilderWiFiForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, http.StatusOK, "builder_wifi.html", map[string]any{
		"Title":      "New Wi-Fi profile",
		"SCEPURL":    a.cfg.SCEPURL,
		"HasAnchors": len(a.cfg.CAAnchorsDER) > 0,
		"Error":      r.URL.Query().Get("error"),
	})
}

func (a *App) handleBuilderWiFi(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	back := "/admin/profiles/new/wifi"
	f := r.PostFormValue

	params := profile.WiFiParams{
		Organization: a.cfg.Organization,
		DisplayName:  strings.TrimSpace(f("display_name")),
		SSID:         strings.TrimSpace(f("ssid")),
		Hidden:       f("hidden") == "on",
		AutoJoin:     f("autojoin") == "on",
	}

	switch f("security") {
	case "eap-tls":
		params.Enterprise = true
		params.SCEPURL = strings.TrimSpace(f("scep_url"))
		params.Challenge = f("scep_challenge")
		params.SubjectCN = strings.TrimSpace(f("subject_cn"))
		if ks, err := strconv.Atoi(f("key_size")); err == nil && ks > 0 {
			params.KeySize = ks
		}
		for _, n := range strings.Split(f("trusted_server_names"), ",") {
			if n = strings.TrimSpace(n); n != "" {
				params.TrustedServerNames = append(params.TrustedServerNames, n)
			}
		}
		// RADIUS trust anchors: Cairn's own (checkbox) and/or a pasted PEM chain.
		if f("use_cairn_anchors") == "on" {
			params.CAAnchorsDER = append(params.CAAnchorsDER, a.cfg.CAAnchorsDER...)
		}
		if pemText := strings.TrimSpace(f("anchors_pem")); pemText != "" {
			anchors, err := ca.TrustAnchorsDER([]byte(pemText))
			if err != nil {
				http.Redirect(w, r, back+"?error="+url.QueryEscape("RADIUS CA chain is not valid PEM: "+err.Error()), http.StatusSeeOther)
				return
			}
			params.CAAnchorsDER = append(params.CAAnchorsDER, anchors...)
		}
	default: // psk
		params.Password = f("password")
	}

	prof, err := profile.BuildWiFi(params)
	if err != nil {
		http.Redirect(w, r, back+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	a.saveBuiltProfile(w, r, prof, "builder:wifi", back)
}

func (a *App) handleBuilderSSOForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, r, http.StatusOK, "builder_sso.html", map[string]any{
		"Title": "New Kerberos SSO profile",
		"Error": r.URL.Query().Get("error"),
	})
}

func (a *App) handleBuilderSSO(w http.ResponseWriter, r *http.Request) {
	limitForm(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !a.checkCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	back := "/admin/profiles/new/sso"
	f := r.PostFormValue

	var hosts []string
	for _, h := range strings.FieldsFunc(f("hosts"), func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}

	prof, err := profile.BuildKerberosSSO(profile.KerberosSSOParams{
		Organization:         a.cfg.Organization,
		DisplayName:          strings.TrimSpace(f("display_name")),
		Realm:                f("realm"),
		Hosts:                hosts,
		DefaultRealm:         f("default_realm") == "on",
		SyncLocalPassword:    f("sync_local_password") == "on",
		AllowAutomaticLogin:  f("allow_automatic_login") == "on",
		UseSiteAutoDiscovery: f("use_site_auto_discovery") == "on",
	})
	if err != nil {
		http.Redirect(w, r, back+"?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	a.saveBuiltProfile(w, r, prof, "builder:kerberos-sso", back)
}

// saveBuiltProfile marshals a built profile, round-trips it through the same
// parser uploads go through (self-validation), and saves it to the library.
func (a *App) saveBuiltProfile(w http.ResponseWriter, r *http.Request, prof map[string]any, source, back string) {
	data, err := profile.Marshal(prof)
	if err != nil {
		a.log.Error("marshal built profile", "source", source, "err", err)
		http.Redirect(w, r, back+"?error="+url.QueryEscape("Building the profile failed."), http.StatusSeeOther)
		return
	}
	info, err := profile.ParseInfo(data)
	if err != nil {
		a.log.Error("built profile failed self-validation", "source", source, "err", err)
		http.Redirect(w, r, back+"?error="+url.QueryEscape("Built profile failed validation: "+err.Error()), http.StatusSeeOther)
		return
	}
	id, err := a.profiles.SaveProfile(r.Context(), sqlite.Profile{
		Identifier:   info.Identifier,
		UUID:         info.UUID,
		Name:         info.Name,
		Organization: info.Organization,
		PayloadTypes: strings.Join(info.PayloadTypes, ","),
		Source:       source,
		Data:         data,
	})
	if err != nil {
		a.log.Error("save built profile", "identifier", info.Identifier, "err", err)
		http.Redirect(w, r, back+"?error="+url.QueryEscape("Saving the profile failed."), http.StatusSeeOther)
		return
	}
	a.log.Info("profile built", "id", id, "identifier", info.Identifier, "source", source, "user", sessionFrom(r).Identity.Username)
	http.Redirect(w, r, "/admin/profiles/"+strconv.FormatInt(id, 10)+"?flash="+url.QueryEscape("Profile created."), http.StatusSeeOther)
}
