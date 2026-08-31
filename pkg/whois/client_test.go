package whois

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeWHOISClient has an answer fixed by the test and
// counts how many times it was consulted. The count is what proves the cascade
// stopped, or continued, where it was supposed to.
type fakeWHOISClient struct {
	name           string
	result         DomainResult
	err            error
	calls          int
	networkResult  NetworkResult
	networkErr     error
	networkCalls   int
	historyRecords []DomainHistoryRecord
	historyErr     error
	historyCalls   int
	historyDomain  string
}

func (f *fakeWHOISClient) Name() string { return f.name }

func (f *fakeWHOISClient) LookupDomain(_ context.Context, _ string) (DomainResult, error) {
	f.calls++
	return f.result, f.err
}

func (f *fakeWHOISClient) LookupNetwork(_ context.Context, _ string) (NetworkResult, error) {
	f.networkCalls++
	return f.networkResult, f.networkErr
}

func (f *fakeWHOISClient) LookupDomainHistory(_ context.Context, domain string) ([]DomainHistoryRecord, error) {
	f.historyCalls++
	f.historyDomain = domain
	return f.historyRecords, f.historyErr
}

// answering returns a leg with a partial record: enough to be substantive, not
// enough to satisfy isComplete. Under merge-until-complete this is the
// interesting case, because it is the one that keeps the cascade walking.
func answering(name string) *fakeWHOISClient {
	return &fakeWHOISClient{
		name:   name,
		result: DomainResult{Domain: "example.com", Registrar: name, Sources: []string{name}},
	}
}

func mostlyComplete(name string) *fakeWHOISClient {
	return &fakeWHOISClient{
		name: name,
		result: DomainResult{
			Domain:     "example.com",
			Registrar:  name,
			Registrant: Contact{Organization: "Example Corp"},
			Sources:    []string{name},
		},
	}
}

// complete returns a leg whose record satisfies strict completion, so the cascade
// has no reason to consult anything after it.
func complete(name string) *fakeWHOISClient {
	return &fakeWHOISClient{name: name, result: completeResult(name)}
}

func completeResult(name string) DomainResult {
	result := DomainResult{
		Domain:      "example.com",
		Registrar:   name,
		Expiration:  "2027-08-13T04:00:00Z",
		NameServers: []string{"ns1." + name + ".test"},
		Registrant:  Contact{Organization: "Example Corp", Email: "admin@example.com"},
		Sources:     []string{name},
	}
	result.Normalize()
	return result
}

func failing(name string) *fakeWHOISClient {
	return &fakeWHOISClient{name: name, err: errors.New(name + " unavailable")}
}

// silent answers successfully but holds no record — distinct from an error.
func silent(name string) *fakeWHOISClient {
	return &fakeWHOISClient{name: name}
}

func unkeyed(name string) *fakeWHOISClient {
	return &fakeWHOISClient{name: name, err: ErrNoCredential}
}

// withCommercialLookups makes the free lookups silent and assigns the supplied
// lookups to Whoxy, WhoisFreaks, and WhoisXML, in that fixed order.
func withCommercialLookups(lookups ...WHOISDomainOnlyClient) *WHOIS {
	commercial := []WHOISDomainOnlyClient{
		silent(ProviderWhoxy),
		silent(ProviderWhoisFreaks),
		silent(ProviderWhoisXML),
	}
	copy(commercial, lookups)

	w := New()
	w.RDAPClient = silent(SourceRDAP)
	w.TCP43Client = silent(SourceTCP43)
	w.WhoxyClient = commercial[0]
	w.WhoisFreaksClient = commercial[1]
	w.WhoisXMLClient = commercial[2]
	return w
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
	second := &fakeWHOISClient{
		name: ProviderWhoisFreaks,
		result: DomainResult{
			Domain:     "example.com",
			Expiration: "2027-08-13T04:00:00Z",
			Sources:    []string{ProviderWhoisFreaks},
		},
	}
	third := &fakeWHOISClient{
		name: ProviderWhoisXML,
		result: DomainResult{
			Domain:      "example.com",
			Registrant:  Contact{Organization: "Example Corp", Email: "admin@example.com"},
			NameServers: []string{"ns1.example.com"},
			Sources:     []string{ProviderWhoisXML},
		},
	}

	res, err := withCommercialLookups(first, second, third).LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 1, second.calls, "a partial answer must not end the cascade")
	assert.Equal(t, 1, third.calls, "a still-incomplete record continues to the next lookup")

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

	res, err := withCommercialLookups(first, second, third).LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, ProviderWhoxy, res.Registrar)
	assert.Equal(t, 1, first.calls)
	assert.Zero(t, second.calls, "a complete record leaves nothing to fill")
	assert.Zero(t, third.calls)
}

func TestCascade_UsesStrictCompletionOnlyBeforeTCP43(t *testing.T) {
	rdap := mostlyComplete(SourceRDAP)
	tcp43 := silent(SourceTCP43)
	whoxy := complete(ProviderWhoxy)

	w := New()
	w.RDAPClient = rdap
	w.TCP43Client = tcp43
	w.WhoxyClient = whoxy

	result, err := w.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, "Example Corp", result.RegistrantIdentity)
	assert.Equal(t, 1, rdap.calls)
	assert.Equal(t, 1, tcp43.calls, "RDAP must provide both identity and email to skip TCP-43")
	assert.Zero(t, whoxy.calls, "mostly complete free results must stop before paid providers")
}

func TestCascade_UsesRelaxedCompletionBetweenPaidProviders(t *testing.T) {
	whoxy := mostlyComplete(ProviderWhoxy)
	whoisFreaks := complete(ProviderWhoisFreaks)
	whoisXML := complete(ProviderWhoisXML)

	result, err := withCommercialLookups(whoxy, whoisFreaks, whoisXML).
		LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, "Example Corp", result.RegistrantIdentity)
	assert.Equal(t, 1, whoxy.calls)
	assert.Zero(t, whoisFreaks.calls, "mostly complete paid results must stop the cascade")
	assert.Zero(t, whoisXML.calls)
}

func TestCascade_LeavesUnavailableRegistrantDataEmpty(t *testing.T) {
	result := completeResult(ProviderWhoxy)
	result.Registrant = Contact{}
	first := &fakeWHOISClient{name: ProviderWhoxy, result: result}
	second := answering(ProviderWhoisFreaks)

	res, err := withCommercialLookups(first, second).LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Empty(t, res.RegistrantIdentity)
	assert.Empty(t, res.ContactEmail)
	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 1, second.calls, "privacy keeps the cascade searching for public registrant data")
}

// TestCascade_PassesThroughToNext verifies that a provider
// that errors, or answers with nothing, must not end the cascade.
func TestCascade_PassesThroughToNext(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first *fakeWHOISClient
	}{
		{"first errors", failing(ProviderWhoxy)},
		{"first answers with no record", silent(ProviderWhoxy)},
		{"first has no credential", unkeyed(ProviderWhoxy)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			second := complete(ProviderWhoisFreaks)

			res, err := withCommercialLookups(tc.first, second).LookupDomain(context.Background(), "example.com")

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

	res, err := withCommercialLookups(first, second, third).LookupDomain(context.Background(), "example.com")

	require.Error(t, err)
	assert.Equal(t, DomainResult{}, res)
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

	w := New()
	w.RDAPClient = free
	w.TCP43Client = silent(SourceTCP43)
	w.WhoxyClient = failing(ProviderWhoxy)
	w.WhoisFreaksClient = silent(ProviderWhoisFreaks)
	w.WhoisXMLClient = unkeyed(ProviderWhoisXML)

	res, err := w.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err, "a partial record is a result, not a failure")
	assert.Equal(t, SourceRDAP, res.Registrar)
	assert.Equal(t, "example.com", res.Domain)
}

func TestCascade_PhoneOnlyContactSurvivesFailedTail(t *testing.T) {
	w := New()
	w.RDAPClient = &fakeWHOISClient{
		name:   SourceRDAP,
		result: DomainResult{Billing: Contact{Phone: "+1.4155550100"}},
	}
	w.TCP43Client = failing(SourceTCP43)
	w.WhoxyClient = failing(ProviderWhoxy)
	w.WhoisFreaksClient = failing(ProviderWhoisFreaks)
	w.WhoisXMLClient = failing(ProviderWhoisXML)

	result, err := w.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, "+1.4155550100", result.Billing.Phone)
}

func TestCascade_UsesDNSPTFallbackFromWhoxyAfterTCPFailure(t *testing.T) {
	whoxyResult, err := parseRawDomainResult("example.pt", readDomainFixture(t, "dns_pt.raw"))
	require.NoError(t, err)

	w := New()
	w.RDAPClient = failing(SourceRDAP)
	w.TCP43Client = failing(SourceTCP43)
	w.WhoxyClient = &fakeWHOISClient{name: ProviderWhoxy, result: whoxyResult}
	w.WhoisFreaksClient = failing(ProviderWhoisFreaks)
	w.WhoisXMLClient = failing(ProviderWhoisXML)

	result, err := w.LookupDomain(context.Background(), "example.pt")

	require.NoError(t, err)
	assert.Equal(t, "Example Networks", result.RegistrantIdentity)
	assert.Equal(t, "Example Registrar", result.Admin.Name)
}

// TestCascade_UnregisteredBelievedWhenNothingResolved: with no competing
// evidence, a provider's not-registered verdict stands, and it ends the cascade
// rather than paying the remaining providers to re-confirm it.
func TestCascade_UnregisteredBelievedWhenNothingResolved(t *testing.T) {
	first := &fakeWHOISClient{
		name:   ProviderWhoxy,
		result: DomainResult{Domain: "gone.com", Unregistered: true},
	}
	second := complete(ProviderWhoisFreaks)

	res, err := withCommercialLookups(first, second).LookupDomain(context.Background(), "gone.com")

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
	denier := &fakeWHOISClient{
		name:   ProviderWhoisXML,
		result: DomainResult{Domain: "example.com", Unregistered: true},
	}

	w := New()
	w.RDAPClient = resolved
	w.TCP43Client = silent(SourceTCP43)
	w.WhoxyClient = silent(ProviderWhoxy)
	w.WhoisFreaksClient = silent(ProviderWhoisFreaks)
	w.WhoisXMLClient = denier

	res, err := w.LookupDomain(context.Background(), "example.com")

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
	redacted := &fakeWHOISClient{
		name: SourceRDAP,
		result: DomainResult{
			Domain:     "example.com",
			Registrar:  "Original Registrar",
			Registrant: Contact{Organization: "REDACTED FOR PRIVACY"},
			Sources:    []string{SourceRDAP},
		},
	}
	real := &fakeWHOISClient{
		name: ProviderWhoisXML,
		result: DomainResult{
			Domain:     "example.com",
			Registrant: Contact{Organization: "Example Corp"},
			Sources:    []string{ProviderWhoisXML},
		},
	}

	w := New()
	w.RDAPClient = redacted
	w.TCP43Client = silent(SourceTCP43)
	w.WhoxyClient = silent(ProviderWhoxy)
	w.WhoisFreaksClient = silent(ProviderWhoisFreaks)
	w.WhoisXMLClient = real

	res, err := w.LookupDomain(context.Background(), "example.com")

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

	_, err := withCommercialLookups(first, second).LookupDomain(ctx, "example.com")

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
// request per configured provider; the fixed provider list bounds that cost.
func TestCascade_EveryConsultedProviderIsBilled(t *testing.T) {
	first := answering(ProviderWhoxy)
	second := answering(ProviderWhoisFreaks)
	third := answering(ProviderWhoisXML)

	res, err := withCommercialLookups(first, second, third).LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	require.False(t, res.isComplete(relaxedCompletion), "the record never reached completeness")

	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 1, second.calls, "billed even though the first already answered")
	assert.Equal(t, 1, third.calls, "billed even though two providers already answered")
}

// TestCascade_MissingCredentialCostsNothing is the one failure mode that is
// free: no key means no request, so it is worth distinguishing from a provider
// that was consulted and declined.
func TestCascade_MissingCredentialCostsNothing(t *testing.T) {
	t.Setenv("WHOISXML_API_KEY", "")

	_, err := NewWhoisXMLClient(nil, "").LookupDomain(context.Background(), "example.com")

	assert.ErrorIs(t, err, ErrNoCredential,
		"an unkeyed resolver declines before building a request")
}

// TestWHOIS_AcceptsFakeLookups is the testability payoff of putting every
// source behind Client: a unit test replaces the network through direct field
// assignment.
func TestLookupDomainHistory_UsesFirstNonEmptyProvider(t *testing.T) {
	whoxy := &fakeWHOISClient{name: ProviderWhoxy}
	whoisFreaks := &fakeWHOISClient{name: ProviderWhoisFreaks, historyErr: errors.New("unavailable")}
	whoisXML := &fakeWHOISClient{
		name: ProviderWhoisXML,
		historyRecords: []DomainHistoryRecord{{
			DomainResult: DomainResult{Domain: "example.com", Registrar: "Example Registrar"},
		}},
	}

	records, err := withCommercialLookups(whoxy, whoisFreaks, whoisXML).
		LookupDomainHistory(context.Background(), "www.example.com")

	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "Example Registrar", records[0].Registrar)
	assert.Equal(t, 1, whoxy.historyCalls)
	assert.Equal(t, 1, whoisFreaks.historyCalls)
	assert.Equal(t, 1, whoisXML.historyCalls)
	assert.Equal(t, "example.com", whoisXML.historyDomain)
}

func TestLookupDomainHistory_StopsAfterRecords(t *testing.T) {
	whoxy := &fakeWHOISClient{
		name: ProviderWhoxy,
		historyRecords: []DomainHistoryRecord{{
			DomainResult: DomainResult{Domain: "example.com", Registrar: "Example Registrar"},
		}},
	}
	whoisFreaks := &fakeWHOISClient{name: ProviderWhoisFreaks}

	_, err := withCommercialLookups(whoxy, whoisFreaks).LookupDomainHistory(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, 1, whoxy.historyCalls)
	assert.Zero(t, whoisFreaks.historyCalls)
}

func TestLookupDomainHistory_AllEmptyIsSuccessful(t *testing.T) {
	records, err := withCommercialLookups().LookupDomainHistory(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestLookupDomainHistory_AllFailedReturnsError(t *testing.T) {
	whoxy := &fakeWHOISClient{name: ProviderWhoxy, historyErr: errors.New("whoxy unavailable")}
	whoisFreaks := &fakeWHOISClient{name: ProviderWhoisFreaks, historyErr: errors.New("whoisfreaks unavailable")}
	whoisXML := &fakeWHOISClient{name: ProviderWhoisXML, historyErr: ErrNoCredential}

	records, err := withCommercialLookups(whoxy, whoisFreaks, whoisXML).
		LookupDomainHistory(context.Background(), "example.com")

	require.Error(t, err)
	assert.Nil(t, records)
	assert.ErrorContains(t, err, "all history methods failed")
}

func TestLookupDomainHistory_RejectsInvalidDomain(t *testing.T) {
	_, err := withCommercialLookups().LookupDomainHistory(context.Background(), "127.0.0.1")

	assert.ErrorContains(t, err, "no registrable domain")
}

func TestWHOIS_AcceptsFakeLookups(t *testing.T) {
	w := New()
	w.RDAPClient = complete(SourceRDAP)
	w.TCP43Client = failing(SourceTCP43)
	w.WhoxyClient = failing(ProviderWhoxy)

	res, err := w.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, SourceRDAP, res.Registrar)
}

func TestLookupUsesFixedOrder(t *testing.T) {
	rdap := answering(SourceRDAP)
	tcp43 := answering(SourceTCP43)
	whoxy := answering(ProviderWhoxy)
	freaks := answering(ProviderWhoisFreaks)
	xml := answering(ProviderWhoisXML)

	w := New()
	w.RDAPClient = rdap
	w.TCP43Client = tcp43
	w.WhoxyClient = whoxy
	w.WhoisFreaksClient = freaks
	w.WhoisXMLClient = xml

	result, err := w.LookupDomain(context.Background(), "example.com")

	require.NoError(t, err)
	assert.Equal(t, []string{
		SourceRDAP,
		SourceTCP43,
		ProviderWhoxy,
		ProviderWhoisFreaks,
		ProviderWhoisXML,
	}, result.Sources)
}

func TestNewAcceptsInformalOptions(t *testing.T) {
	rdap := silent(SourceRDAP)
	w := New(func(w *WHOIS) {
		w.RDAPClient = rdap
	})

	assert.Same(t, rdap, w.RDAPClient)
}

func TestNewPassesAPIKeysToDefaultProviderClients(t *testing.T) {
	w := New(
		WithWhoxyAPIKey("whoxy-option"),
		WithWhoisXMLAPIKey("xml-option"),
		WithWhoisFreaksAPIKey("freaks-option"),
	)

	assert.Equal(t, "whoxy-option", w.WhoxyClient.(*WhoxyClient).apiKey)
	assert.Equal(t, "xml-option", w.WhoisXMLClient.(*WhoisXMLClient).apiKey)
	assert.Equal(t, "freaks-option", w.WhoisFreaksClient.(*WhoisFreaksClient).apiKey)
}

func TestExplicitAPIKeysTakePrecedenceOverEnvironment(t *testing.T) {
	t.Setenv("WHOXY_API_KEY", "whoxy-env")
	t.Setenv("WHOISXML_API_KEY", "xml-env")
	t.Setenv("WHOISFREAKS_API_KEY", "freaks-env")

	w := New(
		WithWhoxyAPIKey("whoxy-option"),
		WithWhoisXMLAPIKey("xml-option"),
		WithWhoisFreaksAPIKey("freaks-option"),
	)

	assert.Equal(t, "whoxy-option", w.WhoxyClient.(*WhoxyClient).getAPIKey())
	assert.Equal(t, "xml-option", w.WhoisXMLClient.(*WhoisXMLClient).resolveAPIKey())
	assert.Equal(t, "freaks-option", w.WhoisFreaksClient.(*WhoisFreaksClient).resolveAPIKey())
}

func TestNewBuildsTheDefaultCascade(t *testing.T) {
	w := New()

	require.NotNil(t, w.RDAPClient)
	require.NotNil(t, w.TCP43Client)
	require.NotNil(t, w.WhoxyClient)
	require.NotNil(t, w.WhoisFreaksClient)
	require.NotNil(t, w.WhoisXMLClient)

	assert.Equal(t, SourceRDAP, w.RDAPClient.Name())
	assert.Equal(t, SourceTCP43, w.TCP43Client.Name())
	assert.Equal(t, ProviderWhoxy, w.WhoxyClient.Name())
	assert.Equal(t, ProviderWhoisFreaks, w.WhoisFreaksClient.Name())
	assert.Equal(t, ProviderWhoisXML, w.WhoisXMLClient.Name())
}

// TestResultIsComplete pins the stop condition. It is a cost dial: every field
// added here bills more providers on every lookup that lacks it.
func TestResultIsComplete(t *testing.T) {
	tests := []struct {
		name        string
		result      DomainResult
		wantRelaxed bool
		wantStrict  bool
	}{
		{
			name: "public identity, email, and registrar",
			result: DomainResult{
				RegistrantIdentity: "Example Corp",
				ContactEmail:       "admin@example.com",
				Registrar:          "Example Registrar",
			},
			wantRelaxed: true,
			wantStrict:  true,
		},
		{
			name: "public identity and registrar",
			result: DomainResult{
				RegistrantIdentity: "Example Corp",
				Registrar:          "Example Registrar",
			},
			wantRelaxed: true,
		},
		{
			name: "public email and registrar",
			result: DomainResult{
				ContactEmail: "admin@example.com",
				Registrar:    "Example Registrar",
			},
			wantRelaxed: true,
		},
		{
			name: "public email and registrar with private identity",
			result: DomainResult{
				RegistrantIdentity: PrivacyRedaction,
				ContactEmail:       "admin@example.com",
				Registrar:          "Example Registrar",
			},
			wantRelaxed: true,
		},
		{
			name: "public identity and registrar with private email",
			result: DomainResult{
				RegistrantIdentity: "Example Corp",
				ContactEmail:       PrivacyRedaction,
				Registrar:          "Example Registrar",
			},
			wantRelaxed: true,
		},
		{name: "empty", result: DomainResult{}},
		{name: "identity without registrar", result: DomainResult{RegistrantIdentity: "Example Corp"}},
		{name: "email without registrar", result: DomainResult{ContactEmail: "admin@example.com"}},
		{name: "registrar without ownership", result: DomainResult{Registrar: "Example Registrar"}},
		{
			name: "public identity and email with private registrar",
			result: DomainResult{
				RegistrantIdentity: "Example Corp",
				ContactEmail:       "admin@example.com",
				Registrar:          PrivacyRedaction,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.wantRelaxed, test.result.isComplete(relaxedCompletion))
			assert.Equal(t, test.wantStrict, test.result.isComplete(strictCompletion))
		})
	}
}

// TestLaterResultMergesRatherThanReplaces guards the gap-filling contract: a
// later source fills what earlier ones left empty and never overwrites what
// they supplied.
func TestLaterResultMergesRatherThanReplaces(t *testing.T) {
	base := DomainResult{
		Domain:    "example.com",
		Registrar: "Original Registrar",
		Created:   "1995-08-14T04:00:00Z",
		Sources:   []string{SourceRDAP},
	}
	later := DomainResult{
		Domain:     "example.com",
		Registrar:  "Different Registrar",
		Expiration: "2027-08-13T04:00:00Z",
		Registrant: Contact{Organization: "Example Corp"},
		Sources:    []string{ProviderWhoisXML},
	}

	base.Merge(later)

	assert.Equal(t, "Original Registrar", base.Registrar, "existing values must survive")
	assert.Equal(t, "1995-08-14T04:00:00Z", base.Created)
	assert.Equal(t, "2027-08-13T04:00:00Z", base.Expiration, "gaps must be filled")
	assert.Equal(t, "Example Corp", base.Registrant.Organization)
	assert.Equal(t, []string{SourceRDAP, ProviderWhoisXML}, base.Sources, "provenance accumulates")
}
