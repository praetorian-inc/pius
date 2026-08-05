package domains

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findingByValue indexes findings for assertions that target one value.
func findingByValue(findings []plugins.Finding, value string) (plugins.Finding, bool) {
	for _, f := range findings {
		if f.Value == value {
			return f, true
		}
	}
	return plugins.Finding{}, false
}

// ── crt-sh ───────────────────────────────────────────────────────────────────

func TestCrtShEvidence_BeneathKnownDomain(t *testing.T) {
	confidence := crtShEvidence("api.acme.com", "acme.com", true)

	assert.InDelta(t, confCTBeneathKnownDomain, confidence.Score, 0.001)
	assert.Equal(t,
		`Certificate Transparency logs contain "api.acme.com" in results for known domain "acme.com"`,
		confidence.Justification)
	assert.False(t, plugins.NeedsReview(plugins.Finding{Confidences: []plugins.Confidence{confidence}}))
}

// TestCrtShEvidence_SharedCertificateIsWeaker: a name co-listed on the target's
// certificate is a different claim from a name inside the target's zone. Shared
// hosting bundles unrelated tenants into one SAN list.
func TestCrtShEvidence_SharedCertificateIsWeaker(t *testing.T) {
	confidence := crtShEvidence("unrelated.example.net", "acme.com", true)

	assert.InDelta(t, confCTSharedCertificate, confidence.Score, 0.001)
	assert.Equal(t,
		`Certificate Transparency logs list "unrelated.example.net" on a certificate returned for known domain "acme.com"`,
		confidence.Justification)
	assert.True(t, plugins.NeedsReview(plugins.Finding{Confidences: []plugins.Confidence{confidence}}))
}

func TestCrtShEvidence_OrganizationQueryStaysAtReviewLevel(t *testing.T) {
	confidence := crtShEvidence("example.net", "Acme Corp", false)

	assert.InDelta(t, confCTOrganizationQuery, confidence.Score, 0.001)
	assert.Equal(t,
		`Certificate Transparency logs contain "example.net" in results for organization query "Acme Corp"`,
		confidence.Justification)
	assert.True(t, plugins.NeedsReview(plugins.Finding{Confidences: []plugins.Confidence{confidence}}))
}

func TestCrtShEvidence_ApexItselfCountsAsBeneath(t *testing.T) {
	assert.InDelta(t, confCTBeneathKnownDomain, crtShEvidence("acme.com", "acme.com", true).Score, 0.001)
}

func TestCrtShPlugin_Run_ScoresAndRetainsCertificateID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `[{"name_value":"api.acme.com\nwww.acme.com","id":123456789}]`)
	}))
	defer srv.Close()

	p := &CRTShPlugin{client: client.New(), baseURL: srv.URL}

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com", OrgName: "Acme Corp"})
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for _, f := range findings {
		require.Len(t, f.Confidences, 1, "unscored crt.sh finding %q", f.Value)
		assert.InDelta(t, confCTBeneathKnownDomain, f.Confidences[0].Score, 0.001)
		assert.Equal(t, "name_value", f.Data["field"])
		assert.Equal(t, int64(123456789), f.Data["crtsh_id"])
	}
}

// ── passive-dns ──────────────────────────────────────────────────────────────

func TestDescribePassiveDNSObservation_SaysHistorical(t *testing.T) {
	described := describePassiveDNSObservation("api.acme.com", "acme.com")

	assert.Equal(t,
		`SecurityTrails reports historical subdomain "api.acme.com" beneath the known domain "acme.com"`,
		described)
	assert.Contains(t, described, "historical",
		"include_inactive=true means the record may be long dead")
}

// TestPassiveDNSEvidence_NeedsReview: a name that may have been retired years
// ago must reach a human, so the score sits just under the clean threshold.
func TestPassiveDNSEvidence_NeedsReview(t *testing.T) {
	finding := plugins.Finding{Confidences: []plugins.Confidence{{
		Score:         confPassiveDNSHistorical,
		Justification: describePassiveDNSObservation("api.acme.com", "acme.com"),
	}}}

	assert.True(t, plugins.NeedsReview(finding))
	assert.GreaterOrEqual(t, confPassiveDNSHistorical, plugins.ConfidenceLow)
}

// ── urlscan ──────────────────────────────────────────────────────────────────

func TestDescribeURLScanObservation_SingleField(t *testing.T) {
	assert.Equal(t,
		`URLScan public scan history observed "api.acme.com" as a page domain beneath "acme.com"`,
		describeURLScanObservation("api.acme.com", "acme.com", []string{"page"}))
}

func TestDescribeURLScanObservation_BothFields(t *testing.T) {
	assert.Equal(t,
		`URLScan public scan history observed "api.acme.com" as a page domain and a task domain beneath "acme.com"`,
		describeURLScanObservation("api.acme.com", "acme.com", []string{"page", "task"}))
}

// TestURLScanPlugin_Run_RepeatedScansDoNotInflate is the rule for urlscan: many
// scans of one host are many people pasting a link, not corroboration.
func TestURLScanPlugin_Run_RepeatedScansDoNotInflate(t *testing.T) {
	response := urlscanResponse{Results: []urlscanResult{
		{Page: urlscanPage{Domain: "api.acme.com"}, Task: urlscanTask{Domain: "api.acme.com"}},
		{Page: urlscanPage{Domain: "api.acme.com"}, Task: urlscanTask{Domain: "api.acme.com"}},
		{Page: urlscanPage{Domain: "api.acme.com"}, Task: urlscanTask{Domain: "acme.com"}},
	}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)

	api, ok := findingByValue(findings, "api.acme.com")
	require.True(t, ok)
	require.Len(t, api.Confidences, 1, "three scans, one observation")
	assert.InDelta(t, confURLScanObservation, plugins.TotalConfidence(api), 0.001)
	assert.Equal(t, "page,task", api.Data["fields"], "both fields are still on the record")
	assert.Contains(t, api.Confidences[0].Justification, "page domain and a task domain")
}

func TestURLScanPlugin_Run_ExcludesDomainsOutsideTheBase(t *testing.T) {
	response := urlscanResponse{Results: []urlscanResult{
		{Page: urlscanPage{Domain: "api.acme.com"}, Task: urlscanTask{Domain: "tracker.example.net"}},
	}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer srv.Close()

	p := &URLScanPlugin{client: client.New(), baseURL: srv.URL}

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "api.acme.com", findings[0].Value)
}

// ── wayback / common crawl ───────────────────────────────────────────────────

func TestDescribeArchiveObservation_NamesTheArchive(t *testing.T) {
	assert.Equal(t,
		`Wayback Machine archived URLs containing hostname "api.acme.com" beneath "acme.com"`,
		describeArchiveObservation(archiveWayback, "api.acme.com", "acme.com"))
	assert.Equal(t,
		`Common Crawl indexed URLs containing hostname "api.acme.com" beneath "acme.com"`,
		describeArchiveObservation(archiveCommonCrawl, "api.acme.com", "acme.com"))
}

// TestWaybackPlugin_Run_ArchivesStayDistinct is the aggregation contract: many
// URLs from one archive collapse, but two archives are two independent crawlers
// and together they clear the threshold.
func TestWaybackPlugin_Run_ArchivesStayDistinct(t *testing.T) {
	wayback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Header row, then several URLs on the same host plus one unique to Wayback.
		_, _ = fmt.Fprint(w, `[["original"],
			["http://api.acme.com/one"],
			["http://api.acme.com/two"],
			["http://old.acme.com/three"]]`)
	}))
	defer wayback.Close()

	commoncrawl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/collinfo.json" {
			_, _ = fmt.Fprintf(w, `[{"cdx-api":"%s/cdx"}]`, r.Host)
			return
		}
		_, _ = fmt.Fprint(w, "{\"url\":\"http://api.acme.com/four\"}\n{\"url\":\"http://api.acme.com/five\"}\n")
	}))
	defer commoncrawl.Close()

	p := &WaybackPlugin{client: client.New(), waybackURL: wayback.URL, commoncrawlURL: commoncrawl.URL}

	findings, err := p.Run(context.Background(), plugins.Input{Domain: "acme.com"})
	require.NoError(t, err)

	api, ok := findingByValue(findings, "api.acme.com")
	require.True(t, ok, "api.acme.com should be found")
	require.Len(t, api.Confidences, 2, "one entry per archive, not per archived URL")
	assert.Equal(t, "Wayback Machine,Common Crawl", api.Data["archives"])
	assert.InDelta(t, 2*confArchiveObservation, plugins.TotalConfidence(api), 0.001)
	assert.False(t, plugins.NeedsReview(api),
		"two independent archives corroborate each other into a clean finding")

	old, ok := findingByValue(findings, "old.acme.com")
	require.True(t, ok)
	require.Len(t, old.Confidences, 1, "one archive, one entry")
	assert.True(t, plugins.NeedsReview(old), "a single historical sighting still needs a human")
}

// TestArchiveEvidenceIsHistoricalAndWeak pins the calibration: an archive record
// is weaker than a live resolution and weaker than a CT entry.
func TestArchiveEvidenceIsHistoricalAndWeak(t *testing.T) {
	assert.Less(t, confArchiveObservation, confPassiveDNSHistorical)
	assert.Less(t, confArchiveObservation, confCTBeneathKnownDomain)
	assert.Less(t, confArchiveObservation, confDNSResolvedNonWildcard)
	assert.GreaterOrEqual(t, confArchiveObservation, plugins.ConfidenceLow)
}
