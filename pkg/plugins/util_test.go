package plugins

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnique_PreservesFirstOccurrenceOrder(t *testing.T) {
	got := Unique([]string{"b.com", "a.com", "b.com", "c.com", "a.com"})
	assert.Equal(t, []string{"b.com", "a.com", "c.com"}, got)
}

func TestUnique_EmptyAndNil(t *testing.T) {
	assert.Nil(t, Unique([]string{}))
	assert.Nil(t, Unique[string](nil))
}

func TestUnique_NoDuplicatesIsUnchanged(t *testing.T) {
	in := []string{"a", "b", "c"}
	assert.Equal(t, in, Unique(in))
}

func TestUniqueBy_DeduplicatesOnKey(t *testing.T) {
	type record struct {
		domain string
		rank   int
	}
	got := UniqueBy([]record{
		{"a.com", 1}, {"b.com", 2}, {"a.com", 3},
	}, func(r record) string { return r.domain })

	assert.Equal(t, []record{{"a.com", 1}, {"b.com", 2}}, got)
}

// First-wins is the contract callers rely on to choose a survivor by sorting.
func TestUniqueBy_FirstKeyWinsSoSortingSelectsTheSurvivor(t *testing.T) {
	type record struct {
		domain string
		year   int
	}
	// Already sorted newest-first, as the reverse-whois plugins do.
	got := UniqueBy([]record{
		{"a.com", 2025}, {"a.com", 2017},
	}, func(r record) string { return r.domain })

	assert.Equal(t, []record{{"a.com", 2025}}, got)
}
