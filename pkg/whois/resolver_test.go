package whois

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResolver is a Resolver whose answer is fixed by the test, and which
// counts how many times it was consulted. The count is what proves the cascade
// stopped, or continued, where it was supposed to.
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

// answering returns a leg with a partial record: enough to be substantive, not
// enough to satisfy isComplete. Under merge-until-complete this is the
// interesting case, because it is the one that keeps the cascade walking.
func answering(name string) *fakeResolver {
	return &fakeResolver{
		name:   name,
		result: Result{Domain: "example.com", Registrar: name, Sources: []string{name}},
	}
}

// complete returns a leg whose record satisfies isComplete, so the cascade has
// no reason to consult anything after it.
func complete(name string) *fakeResolver {
	return &fakeResolver{name: name, result: completeResult(name)}
}

func completeResult(name string) Result {
	return Result{
		Domain:      "example.com",
		Registrar:   name,
		Expiration:  "2027-08-13T04:00:00Z",
		NameServers: []string{"ns1." + name + ".test"},
		Registrant:  Contact{Organization: "Example Corp", Email: "admin@example.com"},
		Sources:     []string{name},
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

// route builds a commercial-only cascade. The free legs are left nil, which the
// cascade skips, so these tests exercise the configurable tail in isolation.
func route(resolvers ...Resolver) *WHOIS {
	return &WHOIS{Fallbacks: resolvers}
}

// TestCascade_ContinuesWhileIncomplete is the core of the resolution model: a
// leg that answers with a partial record does NOT end the cascade. Every later
// provider is consulted, and their fields are merged in.
//
// This is the deliberate inversion of the previous stop-at-first-answer
// behaviour, requested in review on #161. Read
// TestCascade_EveryConsultedProviderIsBilled for what it costs.
func TestCascade_ContinuesWhileIncomplete(t *testing.T) {
	first := answering(ProviderWhoxy)
	second := &fakeResolver{
		name: ProviderWhoisFreaks,
		result: Result{
			Domain:     "example.com",
			Expiration: "2027-08-13T04:00:00Z",
			Sources:    []string{ProviderWhoisFreaks},
		},
	}
	third := &fakeResolver{
		name: ProviderWhoisXML,
		result: Result{
			Domain:      "example.com",
			Registrant:  Contact{Organization: "Example Corp", Email: "admin@example.com"},
			NameServers: []string{"ns1.example.com"},
			Sources:     []string{ProviderWhoisXML},
		},
	}

	res, err := route(first, second, third).Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 1, second.calls, "a partial answer must not end the cascade")
	assert.Equal(t, 1, third.calls, "a still-incomplete record keeps walking the route")

	// Each leg contributed the field the earlier ones left empty.
	assert.Equal(t, ProviderWhoxy, res.Registrar)
	assert.Equal(t, "2027-08-13T04:00:00Z", res.Expiration)
	assert.Equal(t, "Example Corp", res.Registrant.Organization)
	assert.Equal(t, []string{ProviderWhoxy, ProviderWhoisFreaks, ProviderWhoisXML}, res.Sources,
		"provenance accumulates across every leg that contributed")
}

// TestCascade_StopsWhenComplete is the other half of the contract: completeness
// is what ends the cascade, so a leg that answers in full spares every provider
// behind it.
func TestCascade_StopsWhenComplete(t *testing.T) {
	first := complete(ProviderWhoxy)
	second := answering(ProviderWhoisFreaks)
	third := answering(ProviderWhoisXML)

	res, err := route(first, second, third).Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, ProviderWhoxy, res.Registrar)
	assert.Equal(t, 1, first.calls)
	assert.Zero(t, second.calls, "a complete record leaves nothing to fill")
	assert.Zero(t, third.calls)
}

// TestCascade_OrderIsHonoured proves the route is the operator's, not a
// hardcoded preference. Merge is first-non-empty-wins, so order is also field
// precedence: the same two providers in the other order give the other answer.
func TestCascade_OrderIsHonoured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order []string
	}{
		{"whoxy first", []string{ProviderWhoxy, ProviderWhoisXML}},
		{"whoisxml first", []string{ProviderWhoisXML, ProviderWhoxy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := route(complete(tc.order[0]), complete(tc.order[1])).
				Lookup(context.Background(), "example.com")

			require.NoError(t, err)
			assert.Equal(t, tc.order[0], res.Registrar,
				"the leg configured first sets the field")
		})
	}
}

// TestCascade_PassesThroughToNext covers the reason a route exists: a provider
// that errors, or answers with nothing, must not end the cascade.
func TestCascade_PassesThroughToNext(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first *fakeResolver
	}{
		{"first errors", failing(ProviderWhoxy)},
		{"first answers with no record", silent(ProviderWhoxy)},
		{"first has no credential", unkeyed(ProviderWhoxy)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			second := complete(ProviderWhoisFreaks)

			res, err := route(tc.first, second).Lookup(context.Background(), "example.com")

			require.NoError(t, err)
			assert.Equal(t, ProviderWhoisFreaks, res.Registrar)
			assert.Equal(t, 1, tc.first.calls)
			assert.Equal(t, 1, second.calls)
		})
	}
}

// TestCascade_Exhaustion reports failure without inventing a result, and
// surfaces every provider's reason so a caller can say why the cascade came up
// empty.
func TestCascade_Exhaustion(t *testing.T) {
	first := failing(ProviderWhoxy)
	second := silent(ProviderWhoisFreaks)
	third := unkeyed(ProviderWhoisXML)

	res, err := route(first, second, third).Lookup(context.Background(), "example.com")

	require.Error(t, err)
	assert.Equal(t, Result{}, res)
	assert.Contains(t, err.Error(), "whoxy unavailable")
	assert.ErrorIs(t, err, ErrNoCredential)

	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 1, second.calls)
	assert.Equal(t, 1, third.calls, "every provider should be tried before giving up")
}

// TestCascade_PartialResultSurvivesAFailedTail is the exhaustion case that
// matters in production: the free legs supplied something, every paid provider
// then failed, and the partial record is still returned successfully rather
// than thrown away as an error.
func TestCascade_PartialResultSurvivesAFailedTail(t *testing.T) {
	free := answering(SourceRDAP)
	w := &WHOIS{
		RDAPResolver: free,
		Fallbacks:    []Resolver{failing(ProviderWhoxy), unkeyed(ProviderWhoisXML)},
	}

	res, err := w.Lookup(context.Background(), "example.com")

	require.NoError(t, err, "a partial record is a result, not a failure")
	assert.Equal(t, SourceRDAP, res.Registrar)
	assert.Equal(t, "example.com", res.Domain)
}

// TestCascade_EmptyRouteResolvesFromFreeLegsAlone is the no-fallback
// configuration: nothing commercial is consulted and nothing is billed.
func TestCascade_EmptyRouteResolvesFromFreeLegsAlone(t *testing.T) {
	for _, fallbacks := range [][]Resolver{nil, {}} {
		w := &WHOIS{
			RDAPResolver:  complete(SourceRDAP),
			TCP43Resolver: answering(SourceTCP43),
			Fallbacks:     fallbacks,
		}

		res, err := w.Lookup(context.Background(), "example.com")

		require.NoError(t, err)
		assert.Equal(t, SourceRDAP, res.Registrar)
	}
}

// TestCascade_UnregisteredBelievedWhenNothingResolved: with no competing
// evidence, a provider's not-registered verdict stands, and it ends the cascade
// rather than paying the remaining providers to re-confirm it.
func TestCascade_UnregisteredBelievedWhenNothingResolved(t *testing.T) {
	first := &fakeResolver{
		name:   ProviderWhoxy,
		result: Result{Domain: "gone.com", Unregistered: true},
	}
	second := complete(ProviderWhoisFreaks)

	res, err := route(first, second).Lookup(context.Background(), "gone.com")

	require.NoError(t, err)
	assert.True(t, res.Unregistered)
	assert.Equal(t, "gone.com", res.Domain)
	assert.Zero(t, second.calls, "a verdict ends the cascade")
}

// TestCascade_UnregisteredDiscardedAfterARecord: a leg already returned a
// record, so a later provider claiming the domain does not exist is
// contradicting better evidence. Believing it would mark a live domain dead —
// and in Guard that verdict is persisted as a cacheable success, so it sticks.
func TestCascade_UnregisteredDiscardedAfterARecord(t *testing.T) {
	resolved := answering(SourceRDAP)
	denier := &fakeResolver{
		name:   ProviderWhoisXML,
		result: Result{Domain: "example.com", Unregistered: true},
	}

	w := &WHOIS{RDAPResolver: resolved, Fallbacks: []Resolver{denier}}
	res, err := w.Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, 1, denier.calls)
	assert.False(t, res.Unregistered, "a resolved record must not be marked unregistered")
	assert.Equal(t, SourceRDAP, res.Registrar)
	assert.Equal(t, []string{SourceRDAP}, res.Sources,
		"a discarded verdict adds no provenance")
}

// TestCascade_ScrubsBeforeMerging guards an ordering that is easy to get wrong.
// A privacy placeholder must not occupy a field and block the real value a
// later leg carries. Scrubbing the merged record at the end instead would clear
// the placeholder but lose the real name with it.
func TestCascade_ScrubsBeforeMerging(t *testing.T) {
	redacted := &fakeResolver{
		name: SourceRDAP,
		result: Result{
			Domain:     "example.com",
			Registrar:  "Original Registrar",
			Registrant: Contact{Organization: "REDACTED FOR PRIVACY"},
			Sources:    []string{SourceRDAP},
		},
	}
	real := &fakeResolver{
		name: ProviderWhoisXML,
		result: Result{
			Domain:     "example.com",
			Registrant: Contact{Organization: "Example Corp"},
			Sources:    []string{ProviderWhoisXML},
		},
	}

	w := &WHOIS{RDAPResolver: redacted, Fallbacks: []Resolver{real}}
	res, err := w.Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, "Example Corp", res.Registrant.Organization,
		"a placeholder must not block a later leg's real value")
	assert.Equal(t, "Original Registrar", res.Registrar, "real values still take precedence")
}

// TestCascade_StopsOnCancelledContext: a cancelled context fails every
// remaining provider identically, so continuing only produces duplicate errors
// and log noise.
func TestCascade_StopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	first := complete(ProviderWhoxy)
	second := complete(ProviderWhoisFreaks)

	_, err := route(first, second).Lookup(ctx, "example.com")

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, first.calls, "no provider should be consulted once the context is done")
	assert.Zero(t, second.calls)
}

// TestCascade_EveryConsultedProviderIsBilled states the cost of
// merge-until-complete plainly, so nobody reads "merges the best fields" as
// "cheap".
//
// Under stop-at-first-answer, reaching the third provider needed the first two
// to fail. Under merge-until-complete, all three are consulted whenever the
// record stays incomplete — which is the normal outcome for a GDPR-redacted
// domain, because registrant identity is stripped at the registry and is
// therefore absent from every provider. So the common case is one billable
// request per configured provider, and a short default route is the only thing
// bounding it.
func TestCascade_EveryConsultedProviderIsBilled(t *testing.T) {
	first := answering(ProviderWhoxy)
	second := answering(ProviderWhoisFreaks)
	third := answering(ProviderWhoisXML)

	res, err := route(first, second, third).Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	require.False(t, res.isComplete(), "the record never reached completeness")

	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 1, second.calls, "billed even though the first already answered")
	assert.Equal(t, 1, third.calls, "billed even though two providers already answered")
}

// TestCascade_MissingCredentialCostsNothing is the one failure mode that is
// free: no key means no request, so it is worth distinguishing from a provider
// that was consulted and declined.
func TestCascade_MissingCredentialCostsNothing(t *testing.T) {
	t.Setenv("WHOISXML_API_KEY", "")

	_, err := NewWhoisXMLResolver(nil, "").Lookup(context.Background(), "example.com")

	assert.ErrorIs(t, err, ErrNoCredential,
		"an unkeyed resolver declines before building a request")
}

// TestWHOIS_AcceptsFakeLegs is the testability payoff of putting every leg
// behind Resolver: a unit test replaces the network entirely by assigning
// struct fields, with no package-level function patching.
func TestWHOIS_AcceptsFakeLegs(t *testing.T) {
	w := &WHOIS{
		RDAPResolver:  complete(SourceRDAP),
		TCP43Resolver: failing(SourceTCP43),
		Fallbacks:     []Resolver{failing(ProviderWhoxy)},
	}

	res, err := w.Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, SourceRDAP, res.Registrar)
}

// TestWHOIS_SkipsNilLegs: the zero value plus a tail is a valid commercial-only
// cascade, so an absent leg is skipped rather than panicking.
func TestWHOIS_SkipsNilLegs(t *testing.T) {
	w := &WHOIS{Fallbacks: []Resolver{complete(ProviderWhoxy)}}

	res, err := w.Lookup(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, ProviderWhoxy, res.Registrar)
}

func TestNewBuildsTheDefaultCascade(t *testing.T) {
	w := New()

	require.NotNil(t, w.RDAPResolver)
	require.NotNil(t, w.TCP43Resolver)
	assert.Equal(t, SourceRDAP, w.RDAPResolver.Name())
	assert.Equal(t, SourceTCP43, w.TCP43Resolver.Name())

	require.Len(t, w.Fallbacks, 3)
	assert.Equal(t, ProviderWhoxy, w.Fallbacks[0].Name(),
		"the incumbent leads by default so behaviour is preserved")
	assert.Equal(t, ProviderWhoisFreaks, w.Fallbacks[1].Name())
	assert.Equal(t, ProviderWhoisXML, w.Fallbacks[2].Name())
}

// TestResultIsComplete pins the stop condition. It is a cost dial: every field
// added here bills more providers on every lookup that lacks it.
func TestResultIsComplete(t *testing.T) {
	full := completeResult(ProviderWhoxy)
	require.True(t, full.isComplete())

	for _, tc := range []struct {
		name  string
		strip func(*Result)
	}{
		{"no registrant identity", func(r *Result) { r.Registrant.Organization = "" }},
		{"no registrant email", func(r *Result) { r.Registrant.Email = "" }},
		{"no registrar", func(r *Result) { r.Registrar = "" }},
		{"no expiration", func(r *Result) { r.Expiration = "" }},
		{"no nameservers", func(r *Result) { r.NameServers = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := completeResult(ProviderWhoxy)
			tc.strip(&r)
			assert.False(t, r.isComplete(), "a missing field must keep the cascade walking")
		})
	}
}

// TestFallbackResultMergesRatherThanReplaces guards the gap-filling contract
// the cascade depends on: a later source fills what earlier ones left empty and
// never overwrites what they supplied.
func TestFallbackResultMergesRatherThanReplaces(t *testing.T) {
	base := Result{
		Domain:    "example.com",
		Registrar: "Original Registrar",
		Created:   "1995-08-14T04:00:00Z",
		Sources:   []string{SourceRDAP},
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
	assert.Equal(t, []string{SourceRDAP, ProviderWhoisXML}, base.Sources, "provenance accumulates")
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
		assert.Equal(t, ProviderWhoxy, resolvers[0].Name())
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
