package cidrs

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEDGARResponse_ParsesLiveDocumentProvenance(t *testing.T) {
	response := loadEDGARResponseFixture(t)

	require.Len(t, response.Hits.Hits, 1)
	hit := response.Hits.Hits[0]
	assert.Equal(t, "0001234567-24-001234:filing.htm", hit.ID)
	assert.Equal(t, []string{"0007654321", "0001234567"}, hit.Source.CIKs)
	assert.Equal(t, []string{
		"Acme Holdings, Inc.  (CIK 0007654321)",
		"Acme Corp ACME-1  (CIK 0001234567)",
	}, hit.Source.DisplayNames)
	assert.Equal(t, "10-K", hit.Source.Form)
}

func TestSECDocumentURL_ConstructsDirectArchiveURL(t *testing.T) {
	assert.Equal(t,
		"https://www.sec.gov/Archives/edgar/data/1234567/000123456724001234/filing.htm",
		secDocumentURL("0001234567-24-001234:filing.htm"))
}

func TestSECDocumentURL_RejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name       string
		documentID string
	}{
		{name: "zero filing CIK", documentID: "0000000000-24-001234:filing.htm"},
		{name: "invalid accession", documentID: "1234:filing.htm"},
		{name: "unsafe filename", documentID: "0001234567-24-001234:../filing.htm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Empty(t, secDocumentURL(tt.documentID))
		})
	}
}

func TestFindingsFromEDGARResponse_AddsScoredLiveDocumentEvidence(t *testing.T) {
	response := loadEDGARResponseFixture(t)

	findings := findingsFromEDGARResponse(plugins.Input{OrgName: "Acme Corp"}, response)

	require.Len(t, findings, 1)
	finding := findings[0]
	assert.Equal(t, plugins.FindingCIDRHandle, finding.Type)
	assert.Equal(t, "ACME-1", finding.Value)
	assert.Equal(t, "unknown", finding.Data["registry"])
	require.Len(t, finding.Confidences, 1)
	assert.Equal(t, 55, finding.Confidences[0].Score)
	assert.Equal(t,
		`SEC EDGAR document "0001234567-24-001234:filing.htm" for entity "Acme Corp ACME-1  (CIK 0001234567)" contains apparent RIR organization handle "ACME-1"`,
		finding.Confidences[0].Justification)
	require.Len(t, finding.Confidences[0].References, 1)
	assert.Equal(t, "SEC EDGAR document", finding.Confidences[0].References[0].Label)
	assert.Equal(t, "https://www.sec.gov/Archives/edgar/data/1234567/000123456724001234/filing.htm",
		finding.Confidences[0].References[0].URL)
	assert.NotContains(t, finding.Data, "confidence")
	assert.NotContains(t, finding.Data, "confidences")
}

func TestFindingsFromEDGARResponse_UsesFilingCIKFromAccession(t *testing.T) {
	response := loadEDGARResponseFixture(t)
	response.Hits.Hits[0].Source.CIKs = []string{"0007654321", "0007654321"}

	findings := findingsFromEDGARResponse(plugins.Input{OrgName: "Acme Corp"}, response)

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	require.Len(t, findings[0].Confidences[0].References, 1)
	assert.Equal(t,
		"https://www.sec.gov/Archives/edgar/data/1234567/000123456724001234/filing.htm",
		findings[0].Confidences[0].References[0].URL)
}

func TestFindingsFromEDGARResponse_DeduplicatesHandlesUsingFirstDocument(t *testing.T) {
	response := edgarResponse(
		makeEDGARHit("0001234567-24-001234:first.htm", "0001234567", "Acme Corp ACME-1"),
		makeEDGARHit("0001234567-24-001235:second.htm", "0001234567", "Acme Corp ACME-1"),
	)

	findings := findingsFromEDGARResponse(plugins.Input{OrgName: "Acme Corp"}, response)

	require.Len(t, findings, 1)
	require.Len(t, findings[0].Confidences, 1)
	assert.Contains(t, findings[0].Confidences[0].Justification, "first.htm")
	assert.NotContains(t, findings[0].Confidences[0].Justification, "second.htm")
}

func TestFindingsFromEDGARResponse_RejectsNonRIRPrefixes(t *testing.T) {
	response := edgarResponse(
		makeEDGARHit("0001234567-24-001234:filing.htm", "0001234567", "Acme Corp SEC-123 CIK-456"),
	)

	assert.Empty(t, findingsFromEDGARResponse(plugins.Input{OrgName: "Acme Corp"}, response))
}

func loadEDGARResponseFixture(t *testing.T) EDGARResponse {
	t.Helper()
	body, err := os.ReadFile("testdata/edgar_search_response.json")
	require.NoError(t, err)

	var response EDGARResponse
	require.NoError(t, json.Unmarshal(body, &response))
	return response
}

func makeEDGARHit(id, cik, displayName string) EDGARHit {
	hit := EDGARHit{ID: id}
	if cik != "" {
		hit.Source.CIKs = []string{cik}
	}
	hit.Source.DisplayNames = []string{displayName}
	return hit
}

func edgarResponse(hits ...EDGARHit) EDGARResponse {
	var response EDGARResponse
	response.Hits.Hits = hits
	return response
}
