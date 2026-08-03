package ldap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/dzsec/cairn-mdm/internal/auth"
	"github.com/dzsec/cairn-mdm/internal/config"
)

// fakeConn simulates a directory: a service account, one user, groups.
type fakeConn struct {
	svcDN, svcPW   string
	userDN, userPW string
	entry          *goldap.Entry
	searchErr      error
	bound          string
}

func (f *fakeConn) Bind(dn, pw string) error {
	switch {
	case dn == f.svcDN && pw == f.svcPW, dn == f.userDN && pw == f.userPW:
		f.bound = dn
		return nil
	}
	return goldap.NewError(goldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (f *fakeConn) Search(req *goldap.SearchRequest) (*goldap.SearchResult, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	if f.bound != f.svcDN {
		return nil, errors.New("search before service bind")
	}
	// Only "nick" exists.
	if !strings.Contains(req.Filter, "nick") {
		return &goldap.SearchResult{}, nil
	}
	return &goldap.SearchResult{Entries: []*goldap.Entry{f.entry}}, nil
}

func (f *fakeConn) Close() error { return nil }

func testProvider(t *testing.T, conn Conn, dialErrs map[string]error) *Provider {
	t.Helper()
	cfg := config.LDAPCfg{
		Enabled:      true,
		Servers:      []string{"ldaps://dc1.example.org:636", "ldaps://dc2.example.org:636"},
		BaseDN:       "DC=example,DC=org",
		BindDN:       "CN=svc,CN=Users,DC=example,DC=org",
		BindPassword: "svc-pw",
		GroupRoles: map[string]string{
			// Deliberately different case than the entry's memberOf.
			"cn=cert-admins,cn=users,dc=example,dc=org": "admin",
			"CN=helpdesk,CN=Users,DC=example,DC=org":    "operator",
		},
	}
	p, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	p.dial = func(server string) (Conn, error) {
		if err, ok := dialErrs[server]; ok {
			return nil, err
		}
		return conn, nil
	}
	return p
}

func nickEntry(groups ...string) *goldap.Entry {
	return goldap.NewEntry("CN=Nick,CN=Users,DC=example,DC=org", map[string][]string{
		"sAMAccountName": {"nick"},
		"displayName":    {"Nick D"},
		"memberOf":       groups,
	})
}

func baseConn(entry *goldap.Entry) *fakeConn {
	return &fakeConn{
		svcDN: "CN=svc,CN=Users,DC=example,DC=org", svcPW: "svc-pw",
		userDN: "CN=Nick,CN=Users,DC=example,DC=org", userPW: "hunter2",
		entry: entry,
	}
}

func TestAuthenticateMapsGroupsExplicitly(t *testing.T) {
	ctx := context.Background()

	// Admin group (case differs from mapping) → admin.
	p := testProvider(t, baseConn(nickEntry("CN=Cert-Admins,CN=Users,DC=example,DC=org")), nil)
	id, err := p.Authenticate(ctx, "nick", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if id.Role != auth.RoleAdmin || id.Username != "nick" || id.DisplayName != "Nick D" || id.Provider != "ldap" {
		t.Errorf("identity = %+v", id)
	}

	// Unmapped groups only → default role "user", NEVER admin (the v1 bug).
	p = testProvider(t, baseConn(nickEntry("CN=Domain Users,CN=Users,DC=example,DC=org")), nil)
	id, err = p.Authenticate(ctx, "nick", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if id.Role != auth.RoleUser {
		t.Errorf("unmapped groups got role %q, want user", id.Role)
	}

	// Multiple mapped groups → highest wins.
	p = testProvider(t, baseConn(nickEntry(
		"CN=helpdesk,CN=Users,DC=example,DC=org",
		"CN=cert-admins,CN=Users,DC=example,DC=org")), nil)
	id, _ = p.Authenticate(ctx, "nick", "hunter2")
	if id.Role != auth.RoleAdmin {
		t.Errorf("got %q, want admin (highest of mapped)", id.Role)
	}
}

func TestAuthenticateRejects(t *testing.T) {
	ctx := context.Background()
	p := testProvider(t, baseConn(nickEntry()), nil)

	// Wrong password.
	if _, err := p.Authenticate(ctx, "nick", "wrong"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("wrong password err = %v", err)
	}
	// Unknown user.
	if _, err := p.Authenticate(ctx, "mallory", "hunter2"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("unknown user err = %v", err)
	}
	// Empty password must NOT become an anonymous bind.
	if _, err := p.Authenticate(ctx, "nick", ""); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("empty password err = %v", err)
	}
}

func TestFailoverToSecondServer(t *testing.T) {
	conn := baseConn(nickEntry("CN=cert-admins,CN=Users,DC=example,DC=org"))
	p := testProvider(t, conn, map[string]error{
		"ldaps://dc1.example.org:636": errors.New("connection refused"),
	})
	id, err := p.Authenticate(context.Background(), "nick", "hunter2")
	if err != nil {
		t.Fatalf("failover failed: %v", err)
	}
	if id.Role != auth.RoleAdmin {
		t.Errorf("role = %q", id.Role)
	}

	// All servers down → operational error, not invalid credentials.
	p = testProvider(t, conn, map[string]error{
		"ldaps://dc1.example.org:636": errors.New("refused"),
		"ldaps://dc2.example.org:636": errors.New("refused"),
	})
	if _, err := p.Authenticate(context.Background(), "nick", "hunter2"); errors.Is(err, auth.ErrInvalidCredentials) || err == nil {
		t.Errorf("all-down err = %v, want operational error", err)
	}
}
