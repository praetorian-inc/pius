package domains

import (
	"encoding/json"
	"testing"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractRichPreseeds_FansOutCompaniesAndFiltersNoise(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "Acme Corporation",
			Name:         "DATA REDACTED",
			Email:        "billing@safenames.net",
		},
	}

	findings := extractRichPreseeds(info, "example.com", "whois")
	byType := preseedValuesByType(findings)

	assert.Equal(t, []string{"Acme Corporation"}, byType["whois+company"])
	assert.Equal(t, []string{"Acme Corporation"}, byType["edgar+company"])
	assert.NotContains(t, byType, "whois+name")
	assert.NotContains(t, byType, "whois+email")
}

func TestExtractRichPreseeds_RegistryArtifactsAreDomainAware(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{
			Organization: "NIC Chile (University of Chile)",
			Name:         "Abbott Laboratories",
		},
	}

	cl := preseedValuesByType(extractRichPreseeds(info, "similac.cl", "whois"))
	assert.Equal(t, []string{"Abbott Laboratories"}, cl["whois+company"])
	assert.Equal(t, []string{"Abbott Laboratories"}, cl["edgar+company"])
	assert.NotContains(t, cl["whois+company"], "NIC Chile (University of Chile)")

	com := preseedValuesByType(extractRichPreseeds(info, "similac.com", "whois"))
	assert.Contains(t, com["whois+company"], "NIC Chile (University of Chile)")
	assert.Contains(t, com["edgar+company"], "NIC Chile (University of Chile)")
}

func TestExtractRichPreseeds_CCTLDNamePromotionIsScoped(t *testing.T) {
	info := whoisparser.WhoisInfo{
		Registrant: &whoisparser.Contact{Name: "Example Holdings KK"},
	}

	jp := preseedValuesByType(extractRichPreseeds(info, "example.jp", "whois"))
	assert.Equal(t, []string{"Example Holdings KK"}, jp["whois+company"])
	assert.Equal(t, []string{"Example Holdings KK"}, jp["edgar+company"])

	com := preseedValuesByType(extractRichPreseeds(info, "example.com", "whois"))
	assert.NotContains(t, com, "whois+company")
	assert.NotContains(t, com, "edgar+company")
}

func TestEnrichWhoisRecord_NormalizesPersistedMetadata(t *testing.T) {
	record := whoisRecord{
		method: whoisMethodTCP43,
		raw:    "Registrant data REDACTED FOR PRIVACY",
		info: whoisparser.WhoisInfo{
			Registrant: &whoisparser.Contact{
				Organization: "DATA REDACTED",
				City:         "REDACTED FOR PRIVACY",
			},
			Administrative: &whoisparser.Contact{Email: "owner@example.com"},
			Registrar:      &whoisparser.Contact{Name: "Gandi [Tag = GANDI]"},
		},
	}

	enrichWhoisRecord(&record, "example.com")

	require.NotNil(t, record.info.Registrant)
	assert.Equal(t, privacyRedaction, record.info.Registrant.Organization)
	assert.Equal(t, privacyRedaction, record.info.Registrant.City)
	assert.Equal(t, "owner@example.com", record.info.Registrant.Email)
	assert.Equal(t, "GANDI", record.info.Registrar.Name)
	preseeds := preseedValuesByType(extractRichPreseeds(record.info, "example.com", "whois"))
	assert.NotContains(t, preseeds, "whois+company")
	assert.NotContains(t, preseeds, "edgar+company")

	finding, err := recordFinding("example.com", record, "whois")
	require.NoError(t, err)
	encoded, ok := finding.Data["info"].(string)
	require.True(t, ok)

	var decoded whoisparser.WhoisInfo
	require.NoError(t, json.Unmarshal([]byte(encoded), &decoded))
	assert.Equal(t, record.info, decoded)
}

func TestEnrichWhoisRecord_AdministrativeEmailCreatesRegistrant(t *testing.T) {
	record := whoisRecord{info: whoisparser.WhoisInfo{
		Administrative: &whoisparser.Contact{Email: "owner@example.com"},
	}}

	enrichWhoisRecord(&record, "example.com")

	require.NotNil(t, record.info.Registrant)
	assert.Equal(t, "owner@example.com", record.info.Registrant.Email)
}

func TestEnrichWhoisRecord_ISOCILFallbackUsesHolderParagraph(t *testing.T) {
	raw := "descr: Holder Org Ltd\ne-mail: holder AT example.com\n\nperson: Registrar Contact\ne-mail: registrar AT example.net\n"
	record := whoisRecord{raw: raw}

	enrichWhoisRecord(&record, "example.co.il")

	require.NotNil(t, record.info.Registrant)
	assert.Equal(t, "Holder Org Ltd", record.info.Registrant.Organization)
	assert.Equal(t, "holder@example.com", record.info.Registrant.Email)

	nonIL := whoisRecord{raw: raw}
	enrichWhoisRecord(&nonIL, "example.com")
	assert.Nil(t, nonIL.info.Registrant)
}

func TestEnrichWhoisRecord_ISOCILProxyEmailBecomesRedaction(t *testing.T) {
	record := whoisRecord{raw: "descr: Holder Org Ltd\ne-mail: zzzz03.com@shieldwhois.com\n"}

	enrichWhoisRecord(&record, "example.co.il")

	require.NotNil(t, record.info.Registrant)
	assert.Equal(t, privacyRedaction, record.info.Registrant.Email)
}

func TestEnrichWhoisRecord_RedactionMarkerFillsMissingRegistrantFields(t *testing.T) {
	record := whoisRecord{
		raw:  "Registrant data REDACTED FOR GDPR",
		info: whoisparser.WhoisInfo{Registrant: &whoisparser.Contact{}},
	}

	enrichWhoisRecord(&record, "example.com")

	assert.Equal(t, privacyRedaction, record.info.Registrant.Organization)
	assert.Equal(t, privacyRedaction, record.info.Registrant.Email)
}

func preseedValuesByType(findings []plugins.Finding) map[string][]string {
	values := make(map[string][]string)
	for _, finding := range findings {
		preseedType, ok := finding.Data["preseed_type"].(string)
		if ok {
			values[preseedType] = append(values[preseedType], finding.Value)
		}
	}
	return values
}
