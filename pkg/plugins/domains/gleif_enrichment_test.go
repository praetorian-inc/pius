package domains

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/require"
)

func TestGLEIFPlugin_PreservesAndEnrichesFullRecords(t *testing.T) {
	primary := makeLEI("LEI001", "Acme Corp", "US", false)
	childA := makeLEI("LEI010", "Acme One", "US", false)
	childB := makeLEI("LEI011", "Acme Two", "US", false)
	childA.Attributes.Registration.RegisteredAt.ID = "RA0001"
	childB.Attributes.Registration.RegisteredAt.ID = "RA0001"

	var authorityRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/fuzzycompletions"):
			_, _ = w.Write(gleifFuzzyResp(primary.ID))
		case r.URL.Path == "/lei-records/LEI001":
			_, _ = w.Write(gleifRecordResp(primary))
		case r.URL.Path == "/lei-records/LEI001/direct-children":
			_, _ = w.Write(gleifChildrenResp(1, 1, childA, childB))
		case r.URL.Path == "/lei-records/LEI010":
			_, _ = w.Write(fullRecordResponse(childA, "raw-one"))
		case r.URL.Path == "/lei-records/LEI011":
			_, _ = w.Write(fullRecordResponse(childB, "raw-two"))
		case r.URL.Path == "/registration-authorities/RA0001":
			authorityRequests.Add(1)
			_, _ = w.Write([]byte(`{"data":{"attributes":{"code":"RA0001","organization":{"name":"Registry"}}}}`))
		case strings.HasSuffix(r.URL.Path, "/isins"):
			_, _ = w.Write([]byte(`{"meta":{"goldenCopy":{"publishDate":"2026-01-01"}},"data":[{"id":"US0000000001"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	findings, err := newGLEIFPlugin(server.URL).Run(context.Background(), plugins.Input{OrgName: "Acme Corp"})
	require.NoError(t, err)
	require.Len(t, findings, 2)
	require.Equal(t, int32(1), authorityRequests.Load())

	for _, finding := range findings {
		require.Equal(t, "legal-entity", finding.Data["preseed_type"])
		payload := finding.Data["gleif"].(map[string]any)
		record := payload["record"].(map[string]any)
		require.Contains(t, record, "meta")
		require.NotNil(t, payload["registrationAuthority"])
		require.NotNil(t, payload["isins"])
	}
}

func fullRecordResponse(record leiRecord, marker string) []byte {
	response := map[string]any{
		"meta": map[string]any{"marker": marker},
		"data": record,
	}
	encoded, _ := json.Marshal(response)
	return encoded
}
