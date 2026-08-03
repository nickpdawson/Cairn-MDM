package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nickpdawson/cairn-mdm/internal/version"
)

// Evidence is the machine-readable record of an import run, written to disk
// after a real (non-dry-run) import so a cutover decision has an auditable
// artifact. It is deliberately self-contained: counts, per-row exceptions with
// reasons, the exception-file hash, verification mismatches, disable failures,
// the source row counts, and the destination build that produced it.
type Evidence struct {
	// Timestamps are passed in by the caller (normal Go — time.Now() is fine).
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	// BuildCommit is the destination Cairn build that ran the import.
	BuildCommit string `json:"build_commit"`
	BuildInfo   string `json:"build_info"`

	Ok     bool `json:"ok"`
	DryRun bool `json:"dry_run"`

	Devices      int `json:"devices"`
	Users        int `json:"users"`
	Enrollments  int `json:"enrollments"`
	Associations int `json:"associations"`
	PushCerts    int `json:"push_certs"`
	Disabled     int `json:"disabled"`

	CountsByType  map[string]int `json:"counts_by_type"`
	CountsByTopic map[string]int `json:"counts_by_topic"`
	Source        SourceCounts   `json:"source_row_counts"`

	Exceptions          []SkipEntry `json:"exceptions"`
	ExceptionFileSHA256 string      `json:"exception_file_sha256,omitempty"`
	Mismatches          []string    `json:"mismatches"`
	DisableFailures     []string    `json:"disable_failures"`
}

// BuildEvidence assembles an Evidence record from a finished Report and the
// caller-supplied run window. The destination build commit is read from the
// linked-in version metadata.
func BuildEvidence(rep *Report, startedAt, finishedAt time.Time) Evidence {
	ev := Evidence{
		StartedAt:           startedAt,
		FinishedAt:          finishedAt,
		BuildCommit:         version.Commit,
		BuildInfo:           version.Info(),
		Ok:                  rep.Ok(),
		DryRun:              rep.DryRun,
		Devices:             rep.Devices,
		Users:               rep.Users,
		Enrollments:         rep.Enrollments,
		Associations:        rep.Associations,
		PushCerts:           rep.PushCerts,
		Disabled:            rep.Disabled,
		CountsByType:        rep.CountsByType,
		CountsByTopic:       rep.CountsByTopic,
		Source:              rep.Source,
		Exceptions:          rep.Skipped,
		ExceptionFileSHA256: rep.ExceptionFileSHA256,
		Mismatches:          rep.Mismatches,
		DisableFailures:     rep.DisableFailures,
	}
	if ev.CountsByType == nil {
		ev.CountsByType = map[string]int{}
	}
	if ev.CountsByTopic == nil {
		ev.CountsByTopic = map[string]int{}
	}
	if ev.Exceptions == nil {
		ev.Exceptions = []SkipEntry{}
	}
	if ev.Mismatches == nil {
		ev.Mismatches = []string{}
	}
	if ev.DisableFailures == nil {
		ev.DisableFailures = []string{}
	}
	return ev
}

// WriteEvidence writes the evidence bundle to path as indented JSON with
// owner-only permissions (it names topics and enrollment IDs).
func WriteEvidence(path string, ev Evidence) error {
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write evidence %s: %w", path, err)
	}
	return nil
}

// Summary is the short human-readable outcome for stdout. It states the pass or
// fail verdict; the pass line intentionally defers the cutover authority to the
// human runbook rather than asserting the migration is "safe to point DNS at".
func (r *Report) Summary() string {
	var b strings.Builder
	mode := "imported"
	if r.DryRun {
		mode = "validated (dry run)"
	}
	fmt.Fprintf(&b, "Migration %s:\n", mode)
	fmt.Fprintf(&b, "  devices:            %d\n", r.Devices)
	fmt.Fprintf(&b, "  users:              %d\n", r.Users)
	fmt.Fprintf(&b, "  enrollments:        %d (%d disabled)\n", r.Enrollments, r.Disabled)
	fmt.Fprintf(&b, "  cert associations:  %d\n", r.Associations)
	fmt.Fprintf(&b, "  push certificates:  %d\n", r.PushCerts)
	fmt.Fprintf(&b, "  pending (not migrated): %d\n", r.Source.Pending)
	if len(r.CountsByType) > 0 {
		fmt.Fprintf(&b, "  by type:            %s\n", joinCounts(r.CountsByType))
	}
	if len(r.CountsByTopic) > 0 {
		fmt.Fprintf(&b, "  by topic:           %s\n", joinCounts(r.CountsByTopic))
	}
	for _, s := range r.Skipped {
		mark := "SKIPPED"
		if s.Accepted {
			mark = "SKIPPED (accepted exception)"
		}
		fmt.Fprintf(&b, "  %s: %s: %s\n", mark, s.ID, s.Reason)
	}
	for _, m := range r.Mismatches {
		fmt.Fprintf(&b, "  MISMATCH: %s\n", m)
	}
	for _, d := range r.DisableFailures {
		fmt.Fprintf(&b, "  DISABLE FAILED: %s\n", d)
	}
	if r.DryRun {
		return b.String()
	}
	if r.Ok() {
		b.WriteString("\nVerification passed; the human runbook authorizes cutover.\n")
	} else {
		b.WriteString("\nVerification FAILED — DO NOT CUT OVER.\n")
	}
	return b.String()
}

// joinCounts renders a small count map deterministically-ish for humans. Order
// is not guaranteed (map iteration) but the content is stable.
func joinCounts(m map[string]int) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		label := k
		if label == "" {
			label = "(none)"
		}
		parts = append(parts, fmt.Sprintf("%s=%d", label, v))
	}
	return strings.Join(parts, " ")
}
