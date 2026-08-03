package web

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// parseTrustedProxies turns config entries (each a bare IP or a CIDR) into a
// list of networks. A bare IP becomes a host route (/32 or /128). An empty
// input yields nil — trust no proxy.
func parseTrustedProxies(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return nil, fmt.Errorf("web: trusted_proxies: %q is not an IP or CIDR", e)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// isTrustedProxy reports whether ipStr is within any configured trusted-proxy
// network.
func (a *App) isTrustedProxy(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, n := range a.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the originating client's IP for throttling and audit
// attribution. It uses the direct peer (r.RemoteAddr) unless that peer is a
// configured trusted proxy, in which case it walks X-Forwarded-For from right
// to left and returns the first address that is not itself a trusted proxy —
// the real client as seen by the outermost trusted hop. Untrusted peers can't
// spoof their address this way: their X-Forwarded-For is ignored entirely.
func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if len(a.trusted) == 0 || !a.isTrustedProxy(host) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip == "" || a.isTrustedProxy(ip) {
			continue
		}
		return ip
	}
	return host
}
