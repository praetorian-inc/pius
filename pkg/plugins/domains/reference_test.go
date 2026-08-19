package domains

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

func confidenceReferences(t *testing.T, confidence plugins.Confidence) []plugins.Reference {
	t.Helper()
	require.NotNil(t, confidence.Reference)
	require.Equal(t, plugins.ReferenceTypeJSON, confidence.Reference.Type)
	collection, ok := confidence.Reference.Data.(plugins.URLCollectionReferenceData)
	require.True(t, ok)
	references := make([]plugins.Reference, len(collection.URLs))
	for i, item := range collection.URLs {
		references[i] = *plugins.URLReference(item.Label, item.URL)
	}
	return references
}

func referenceURL(t *testing.T, reference plugins.Reference) string {
	t.Helper()
	require.Equal(t, plugins.ReferenceTypeURL, reference.Type)
	data, ok := reference.Data.(plugins.URLReferenceData)
	require.True(t, ok)
	return data.URL
}
