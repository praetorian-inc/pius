package whois

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResolver is a Resolver whose answer is fixed by the test, and which
// counts how many times it was consulted. The count is what proves the route
// stopped where it was supposed to.
type fakeResolver struct {
	name   string
	result Result
	err    error
	calls  int
}

func (f *fakeResolver) Name() string { return f.name }

func (f *fakeResolver) Lookup(_ context.Context, _ string) (Result, error) {
	f.calls++
	return f.result, f.err
}

func answering(name string) *fakeResolver {
	return &fakeResolver{
		name:   name,
		result: Result{Domain: "example.com", Registrar: name, Sources: []string{name}},
	}
}

func failing(name string) *fakeResolver {
	return &fakeResolver{name: name, err: errors.New(name + " unavailable")}
}

// silent answers successfully but holds no record — distinct from an error.
func silent(name string) *fakeResolver {
	return &fakeResolver{name: name}
}

func unkeyed(name string) *fakeResolver {
	return &fakeResolver{name: name, err: ErrNoCredential}
}

// TestRunFallbacks_StopsAtFirstAnswer is the cost guarantee: once a provider
// answers, no later provider is consulted, so at most one commercial provider
// is billed per lookup.
func TestRunFallbacks_StopsAtFirstAnswer(t *testing.T) {
	first := answering(ProviderWhoxy)
	second := answering(ProviderWhoisFreaks)
	third := answering(ProviderWhoisXML)

	res, ok, err := runFallbacks(context.Background(),
		[]Resolver{first, second, third}, "example.com")

	require.True(t, ok)
	require.NoError(t, err)
	assert.Equal(t, ProviderWhoxy, res.Registrar, "the first provider's record should win")

	assert.Equal(t, 1, first.calls)
	assert.Zero(t, second.calls, "second provider must not be billed once the first answered")
	assert.Zero(t, third.calls, "third provider must not be billed once the first answered")
}

// TestRunFallbacks_OrderIsHonoured proves the route is the operator's, not a
// hardcoded preference: the same providers in the other order give the other
// answer.
func TestRunFallbacks_OrderIsHonoured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order []string
		want  string
	}{
		{"whoxy first", []string{ProviderWhoxy, ProviderWhoisXML}, ProviderWhoxy},
		{"whoisxml first", []string{ProviderWhoisXML, ProviderWhoxy}, ProviderWhoisXML},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolvers := []Resolver{answering(tc.order[0]), answering(tc.order[1])}

			res, ok, err := runFallbacks(context.Background(), resolvers, "example.com")

			require.True(t, ok)
			require.NoError(t, err)
			assert.Equal(t, tc.want, res.Registrar)
		})
	}
}

// TestRunFallbacks_PassesThroughToNext covers the reason a route exists: a
// provider that errors, or that answers with nothing, must not end the chain.
func TestRunFallbacks_PassesThroughToNext(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first *fakeResolver
	}{
		{"first errors", failing(ProviderWhoxy)},
		{"first answers with no record", silent(ProviderWhoxy)},
		{"first has no credential", unkeyed(ProviderWhoxy)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			second := answering(ProviderWhoisFreaks)

			res, ok, _ := runFallbacks(context.Background(),
				[]Resolver{tc.first, second}, "example.com")

			require.True(t, ok)
			assert.Equal(t, ProviderWhoisFreaks, res.Registrar)
			assert.Equal(t, 1, tc.first.calls)
			assert.Equal(t, 1, second.calls)
		})
	}
}

// TestRunFallbacks_Exhaustion reports failure without inventing a result, and
// surfaces every provider's reason so a caller can say why the route came up
// empty.
func TestRunFallbacks_Exhaustion(t *testing.T) {
	first := failing(ProviderWhoxy)
	second := silent(ProviderWhoisFreaks)
	third := unkeyed(ProviderWhoisXML)

	res, ok, err := runFallbacks(context.Background(),
		[]Resolver{first, second, third}, "example.com")

	assert.False(t, ok)
	assert.Equal(t, Result{}, res)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "whoxy unavailable")
	assert.ErrorIs(t, err, ErrNoCredential)

	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 1, second.calls)
	assert.Equal(t, 1, third.calls, "every provider should be tried before giving up")
}

// TestRunFallbacks_EmptyRoute is the no-fallback configuration: nothing is
// consulted and nothing is billed.
func TestRunFallbacks_EmptyRoute(t *testing.T) {
	for _, resolvers := range [][]Resolver{nil, {}} {
		res, ok, err := runFallbacks(context.Background(), resolvers, "example.com")
		assert.False(t, ok)
		assert.Equal(t, Result{}, res)
		assert.NoError(t, err)
	}
}

// TestRunFallbacks_UnregisteredIsAnAnswer: a provider reporting the domain does
// not exist has answered. The route stops; what the caller does with that
// verdict is its own decision.
func TestRunFallbacks_UnregisteredIsAnAnswer(t *testing.T) {
	first := &fakeResolver{
		name:   ProviderWhoxy,
		result: Result{Domain: "gone.com", Unregistered: true},
	}
	second := answering(ProviderWhoisFreaks)

	res, ok, _ := runFallbacks(context.Background(), []Resolver{first, second}, "gone.com")

	require.True(t, ok)
	assert.True(t, res.Unregistered)
	assert.Zero(t, second.calls)
}

// TestFallbackResultMergesRatherThanReplaces guards the gap-filling contract
// the route depends on: a later source fills what earlier ones left empty and
// never overwrites what they supplied.
func TestFallbackResultMergesRatherThanReplaces(t *testing.T) {
	base := Result{
		Domain:    "example.com",
		Registrar: "Original Registrar",
		Created:   "1995-08-14T04:00:00Z",
		Sources:   []string{"rdap"},
	}
	fallback := Result{
		Domain:     "example.com",
		Registrar:  "Different Registrar",
		Expiration: "2027-08-13T04:00:00Z",
		Registrant: Contact{Organization: "Example Corp"},
		Sources:    []string{ProviderWhoisXML},
	}

	base.Merge(fallback)

	assert.Equal(t, "Original Registrar", base.Registrar, "existing values must survive")
	assert.Equal(t, "1995-08-14T04:00:00Z", base.Created)
	assert.Equal(t, "2027-08-13T04:00:00Z", base.Expiration, "gaps must be filled")
	assert.Equal(t, "Example Corp", base.Registrant.Organization)
	assert.Equal(t, []string{"rdap", ProviderWhoisXML}, base.Sources, "provenance accumulates")
}

func TestResolversByName(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "k")
	t.Setenv("WHOISFREAKS_API_KEY", "k")
	t.Setenv("WHOISXML_API_KEY", "k")

	t.Run("builds the named route in order", func(t *testing.T) {
		resolvers, err := ResolversByName(nil,
			ProviderWhoisXML, ProviderWhoxy, ProviderWhoisFreaks)

		require.NoError(t, err)
		require.Len(t, resolvers, 3)
		assert.Equal(t, ProviderWhoisXML, resolvers[0].Name())
		assert.Equal(t, ProviderWhoxy, resolvers[1].Name())
		assert.Equal(t, ProviderWhoisFreaks, resolvers[2].Name())
	})

	t.Run("accepts a single provider", func(t *testing.T) {
		resolvers, err := ResolversByName(nil, ProviderWhoisXML)
		require.NoError(t, err)
		require.Len(t, resolvers, 1)
		assert.Equal(t, ProviderWhoisXML, resolvers[0].Name())
	})

	t.Run("accepts an empty route", func(t *testing.T) {
		resolvers, err := ResolversByName(nil)
		require.NoError(t, err)
		assert.Empty(t, resolvers)
	})

	t.Run("normalises case and whitespace", func(t *testing.T) {
		resolvers, err := ResolversByName(nil, "  WhoisXML  ", "", "WHOXY")
		require.NoError(t, err)
		require.Len(t, resolvers, 2)
		assert.Equal(t, ProviderWhoisXML, resolvers[0].Name())
		assert.Equal(t, ProviderWhoxy, resolvers[1].Name())
	})

	t.Run("rejects an unknown provider rather than silently dropping it", func(t *testing.T) {
		_, err := ResolversByName(nil, ProviderWhoxy, "whoismystery")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "whoismystery")
	})
}

// TestResolversByName_ReportsMissingCredential: a provider the operator asked
// for, with no key, must not fail silently on every lookup for the life of the
// process. It is built and reported, and declines at lookup time.
func TestResolversByName_ReportsMissingCredential(t *testing.T) {
	t.Setenv("WHOISXML_API_KEY", "")

	resolvers, err := ResolversByName(nil, ProviderWhoisXML)
	require.NoError(t, err)
	require.Len(t, resolvers, 1)

	c, ok := resolvers[0].(credentialed)
	require.True(t, ok, "resolver should report whether it is usable")
	assert.False(t, c.hasCredential())

	_, lookupErr := resolvers[0].Lookup(context.Background(), "example.com")
	assert.ErrorIs(t, lookupErr, ErrNoCredential)
}

// TestConfigResolvers distinguishes "no route configured" (use the default)
// from "route explicitly configured as empty" (no commercial fallback).
func TestConfigResolvers(t *testing.T) {
	t.Run("unset uses the default order", func(t *testing.T) {
		cfg := config{}
		resolvers := cfg.resolvers()

		require.Len(t, resolvers, 3)
		assert.Equal(t, ProviderWhoxy, resolvers[0].Name(),
			"the incumbent leads by default so behaviour is preserved")
		assert.Equal(t, ProviderWhoisFreaks, resolvers[1].Name())
		assert.Equal(t, ProviderWhoisXML, resolvers[2].Name())
	})

	t.Run("explicitly empty disables the fallback", func(t *testing.T) {
		cfg := config{}
		WithFallbackResolvers()(&cfg)

		assert.Empty(t, cfg.resolvers())
	})

	t.Run("explicit route replaces the default", func(t *testing.T) {
		cfg := config{}
		WithFallbackResolvers(answering(ProviderWhoisXML))(&cfg)

		resolvers := cfg.resolvers()
		require.Len(t, resolvers, 1)
		assert.Equal(t, ProviderWhoisXML, resolvers[0].Name())
	})
}

func TestDefaultFallbackOrder(t *testing.T) {
	assert.Equal(t,
		[]string{ProviderWhoxy, ProviderWhoisFreaks, ProviderWhoisXML},
		DefaultFallbackOrder())
}
