package cidrs

import (
	"testing"

	"github.com/praetorian-inc/pius/pkg/plugins"
	"github.com/stretchr/testify/require"
)

func confidenceURL(t *testing.T, confidence plugins.Confidence) string {
	t.Helper()
	require.NotNil(t, confidence.Reference)
	require.Equal(t, plugins.ReferenceTypeURL, confidence.Reference.Type)
	data, ok := confidence.Reference.Data.(plugins.URLReferenceData)
	require.True(t, ok)
	return data.URL
}
