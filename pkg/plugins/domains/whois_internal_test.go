package domains

import (
	"testing"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
		{"", ""},
		{"localhost", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, rootDomain(tt.input), "rootDomain(%q)", tt.input)
	}
}

func TestExtractPreseeds_WithContacts(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "Acme Corp",
			Name:         "John Doe",
			Email:        "admin@acme.com",
		},
		Administrative: &whoisparser.Contact{
			Organization: "Acme Corp", // duplicate, should be deduped
			Name:         "Jane Smith",
			Email:        "not-an-email", // invalid, should be skipped
		},
	}

	findings := extractPreseeds("acme.com", info)

	// Expect: company=Acme Corp, name=John Doe, email=admin@acme.com, name=Jane Smith
	// Acme Corp from Administrative is deduped
	require.Len(t, findings, 4)

	types := make(map[string][]string)
	for _, f := range findings {
		assert.Equal(t, plugins.FindingPreseed, f.Type)
		assert.Equal(t, "whois", f.Source)
		pt := f.Data["preseed_type"].(string)
		types[pt] = append(types[pt], f.Value)
	}

	assert.Equal(t, []string{"Acme Corp"}, types["whois+company"])
	assert.ElementsMatch(t, []string{"John Doe", "Jane Smith"}, types["whois+name"])
	assert.Equal(t, []string{"admin@acme.com"}, types["whois+email"])
}

func TestExtractPreseeds_NilContacts(t *testing.T) {
	info := whoisparser.WhoisInfo{}
	findings := extractPreseeds("acme.com", info)
	assert.Empty(t, findings)
}

func TestExtractPreseeds_EmptyFields(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "",
			Name:         "",
			Email:        "",
		},
	}
	findings := extractPreseeds("acme.com", info)
	assert.Empty(t, findings)
}

func TestExtractPreseeds_PrivacyGuardBlocksCompany(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "Domains By Proxy, LLC",
			Name:         "Registration Private",
			Email:        "proxy@domainsbyproxy.com",
		},
	}
	findings := extractPreseeds("acme.com", info)
	for _, f := range findings {
		preseedType, _ := f.Data["preseed_type"].(string)
		assert.NotEqual(t, "whois+company", preseedType, "privacy guard org should be filtered")
	}
}

func TestExtractPreseeds_PrivacyGuardCaseInsensitive(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "DOMAINS BY PROXY, LLC",
		},
	}
	findings := extractPreseeds("acme.com", info)
	for _, f := range findings {
		preseedType, _ := f.Data["preseed_type"].(string)
		assert.NotEqual(t, "whois+company", preseedType, "case-insensitive privacy guard check")
	}
}

func TestExtractPreseeds_LegitimateOrgNotFiltered(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "Acme Corporation",
		},
	}
	findings := extractPreseeds("acme.com", info)
	require.Len(t, findings, 1)
	assert.Equal(t, "whois+company", findings[0].Data["preseed_type"])
	assert.Equal(t, "Acme Corporation", findings[0].Value)
}

// ── confidence by role and field (plan §6) ───────────────────────────────────

func TestExtractPreseeds_RegistrantOrgIsStrongest(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{Organization: "Acme Corporation"},
	}

	findings := extractPreseeds("acme.com", info)

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.InDelta(t, confWhoisRegistrantOrg, findings[0].Confidences[0].Score, 0.001)
	assert.Equal(t, `WHOIS for "acme.com" lists "Acme Corporation" as the registrant organization`,
		findings[0].Confidences[0].Justification)
	assert.Equal(t, "registrant", findings[0].Data["whois_role"])
}

func TestExtractPreseeds_AdministrativeEmailReadsAsContact(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Administrative: &whoisparser.Contact{Email: "security@acme.com"},
	}

	findings := extractPreseeds("acme.com", info)

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.InDelta(t, confWhoisContactValue, findings[0].Confidences[0].Score, 0.001)
	assert.Equal(t, `WHOIS for "acme.com" lists "security@acme.com" as an administrative contact email`,
		findings[0].Confidences[0].Justification)
}

// TestExtractPreseeds_RoleChangesTheScore is the point of retaining the role: the
// same organization string is worth more as the registrant than as the technical
// contact, which is usually the hosting provider.
func TestExtractPreseeds_RoleChangesTheScore(t *testing.T) {
	registrant := extractPreseeds("acme.com", whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{Organization: "Acme Corporation"},
	})
	technical := extractPreseeds("acme.com", whoisparser.WhoisInfo{
		Technical: &whoisparser.Contact{Organization: "Hosting Provider LLC"},
	})

	require.Len(t, registrant, 1)
	require.Len(t, technical, 1)
	assert.Greater(t,
		plugins.TotalConfidence(registrant[0]),
		plugins.TotalConfidence(technical[0]))
	assert.Contains(t, technical[0].Confidences[0].Justification,
		"as the organization of the technical contact")
}

// TestExtractPreseeds_EveryPreseedIsScored is the invariant for this plugin: a
// preseed with no evidence would reach Guard unscored and fall back to a default.
func TestExtractPreseeds_EveryPreseedIsScored(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant:     &whoisparser.Contact{Organization: "Acme Corporation", Name: "Jane Roe", Email: "jane@acme.com"},
		Administrative: &whoisparser.Contact{Organization: "Acme Holdings", Email: "admin@acme.com"},
		Technical:      &whoisparser.Contact{Name: "Ops Team", Email: "ops@acme.com"},
	}

	findings := extractPreseeds("acme.com", info)

	require.NotEmpty(t, findings)
	for _, f := range findings {
		require.NotEmpty(t, f.Confidences, "unscored preseed %q", f.Value)
		assert.NotEmpty(t, f.Confidences[0].Justification, "empty justification for %q", f.Value)
		assert.Greater(t, plugins.TotalConfidence(f), 0.0, "zero-scored preseed %q", f.Value)
	}
}

// TestExtractPreseeds_RepeatedValueKeepsStrongestRole: the registrant and the
// technical contact being the same person is one fact, and the run order means
// the surviving entry is the registrant's.
func TestExtractPreseeds_RepeatedValueKeepsStrongestRole(t *testing.T) {
	shared := &whoisparser.Contact{Organization: "Acme Corporation"}
	info := whoisparser.WhoisInfo{Registrant: shared, Technical: shared}

	findings := extractPreseeds("acme.com", info)

	require.Len(t, findings, 1, "one value, one preseed")
	assert.InDelta(t, confWhoisRegistrantOrg, plugins.TotalConfidence(findings[0]), 0.001)
	assert.Equal(t, "registrant", findings[0].Data["whois_role"])
}

// TestWhoisJustifications_OmitUnrelatedRecordFields keeps third-party PII out of
// the justification: the emitted value is already public as the preseed, but no
// other field of the record may ride along.
func TestWhoisJustifications_OmitUnrelatedRecordFields(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "Acme Corporation",
			Name:         "Jane Roe",
			Email:        "jane@acme.com",
			Street:       "123 Private Road",
			Phone:        "+1-555-0100",
		},
	}

	findings := extractPreseeds("acme.com", info)

	require.NotEmpty(t, findings)
	for _, f := range findings {
		for _, c := range f.Confidences {
			assert.NotContains(t, c.Justification, "123 Private Road")
			assert.NotContains(t, c.Justification, "+1-555-0100")
			assert.Contains(t, c.Justification, f.Value, "the justification should name its own value")
		}
	}
}

func TestWhoisScore_Ordering(t *testing.T) {
	assert.Greater(t, whoisScore(whoisRoleRegistrant, "company"), whoisScore(whoisRoleRegistrant, "name"))
	assert.Greater(t, whoisScore(whoisRoleRegistrant, "company"), whoisScore(whoisRoleTechnical, "company"))
	assert.Greater(t, whoisScore(whoisRoleTechnical, "company"), whoisScore(whoisRoleTechnical, "email"))

	// Nothing WHOIS reports reads as clean on its own; every score stays inside
	// the review band so a human sees it.
	for _, role := range []string{whoisRoleRegistrant, whoisRoleAdministrative, whoisRoleBilling, whoisRoleTechnical} {
		for _, field := range []string{"company", "name", "email"} {
			score := whoisScore(role, field)
			assert.GreaterOrEqual(t, score, plugins.ConfidenceLow, "%s/%s below the noise floor", role, field)
			assert.Less(t, score, plugins.ConfidenceHigh, "%s/%s reads as clean", role, field)
		}
	}
}
