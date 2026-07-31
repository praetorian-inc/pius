package domains

import (
	"net/url"
	"slices"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// excludedTLDs lists top-level domains that are never corporate subsidiaries.
var excludedTLDs = []string{".gov", ".mil", ".edu"}

// hasExcludedTLD returns true if d ends with an excluded TLD suffix.
func hasExcludedTLD(d string) bool {
	for _, tld := range excludedTLDs {
		if strings.HasSuffix(d, tld) {
			return true
		}
	}
	return false
}

// excludedDomains lists non-Google infrastructure and other excluded domains.
// Individual google.* country domains are not listed here because isExcludedDomain
// handles all google.* variants via pattern matching.
var excludedDomains = map[string]bool{
	// Google infrastructure
	"googleapis.com":        true,
	"gstatic.com":           true,
	"googletagmanager.com":  true,
	"googlesyndication.com": true,
	"googleadservices.com":  true,
	"youtube.com":           true,
	"ggpht.com":             true,
	"googleusercontent.com": true,
	// Web standards / encyclopedias
	"schema.org":    true,
	"w3.org":        true,
	"wikipedia.org": true,
	"wikimedia.org": true,
	// Social media
	"linkedin.com":  true,
	"reddit.com":    true,
	"facebook.com":  true,
	"twitter.com":   true,
	"instagram.com": true,
	"x.com":         true,
	"github.com":    true,
	// Business directories / news aggregators
	"crunchbase.com":   true,
	"bloomberg.com":    true,
	"pitchbook.com":    true,
	"businesswire.com": true,
	"prnewswire.com":   true,
	"yahoo.com":        true,
	"techcrunch.com":   true,
	"forbes.com":       true,
	"reuters.com":      true,
	"wsj.com":          true,
	"cnbc.com":         true,
	"preqin.com":       true,
	"justia.com":       true,
	"marketscreener.com": true,
	// Government / regulatory
	"gov.uk":    true,
	"europa.eu": true,
	// Data aggregators
	"dnb.com":                           true,
	"zoominfo.com":                      true,
	"owler.com":                         true,
	"craft.co":                          true,
	"annuaire-entreprises.data.gouv.fr": true,
	"theygotacquired.com":               true,
}

// isExcludedDomain returns true if d is a Google domain, Google-owned infrastructure,
// a government/military/educational domain, or another excluded non-target domain.
func isExcludedDomain(d string) bool {
	d = strings.ToLower(d)

	if hasExcludedTLD(d) {
		return true
	}

	// Check exact match or subdomain of excluded domains.
	if excludedDomains[d] {
		return true
	}
	for excluded := range excludedDomains {
		if strings.HasSuffix(d, "."+excluded) {
			return true
		}
	}

	// Match any google.* domain (google.com, google.es, google.co.uk, etc.).
	parts := strings.Split(d, ".")
	return slices.Contains(parts, "google")
}

// matchesInputDomain returns true if d is the same domain as inputDomain,
// accounting for the presence or absence of a "www." prefix on either side.
func matchesInputDomain(d, inputDomain string) bool {
	return d == inputDomain ||
		d == "www."+inputDomain ||
		inputDomain == "www."+d
}

// extractCarouselNames finds carousel elements with data-entityname attributes and
// returns deduplicated company names.
func extractCarouselNames(sel *goquery.Selection) []string {
	seen := make(map[string]bool)
	var names []string

	sel.Find("a[data-entityname]").Each(func(_ int, s *goquery.Selection) {
		name, exists := s.Attr("data-entityname")
		if !exists || name == "" {
			return
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	})

	return names
}

// extractDomainsFromSelection extracts unique hostnames from <a href> attributes
// within the given goquery selection. Google /url?q= redirect wrappers are unwrapped.
func extractDomainsFromSelection(sel *goquery.Selection) []string {
	seen := make(map[string]bool)
	var domains []string

	sel.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists || href == "" {
			return
		}
		// Google wraps results in /url?q=REAL_URL redirects — unwrap them.
		if strings.HasPrefix(href, "/url?") {
			if u, err := url.Parse(href); err == nil {
				href = u.Query().Get("q")
			}
		}
		if href == "" {
			return
		}
		u, err := url.Parse(href)
		if err != nil || u.Host == "" {
			return
		}
		host := strings.ToLower(u.Hostname())
		if host != "" && !seen[host] {
			seen[host] = true
			domains = append(domains, host)
		}
	})

	return domains
}

// extractOfficialDomain tries to extract the official website domain from
// Google's Knowledge Panel. Returns empty string if not found.
// The Knowledge Panel renders official site links with specific data attributes.
func extractOfficialDomain(sel *goquery.Selection) string {
	// Google Knowledge Panel official site link
	var officialURL string
	sel.Find(`a[data-attrid="visit_official_site"]`).First().Each(func(_ int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists && href != "" {
			officialURL = href
		}
	})
	// Also try the "Website" row in the Knowledge Panel sidebar
	if officialURL == "" {
		sel.Find(`a[class*="ab_button"][href]`).First().Each(func(_ int, s *goquery.Selection) {
			text := strings.TrimSpace(s.Text())
			if strings.EqualFold(text, "Website") || strings.EqualFold(text, "Official site") {
				if href, exists := s.Attr("href"); exists && href != "" {
					officialURL = href
				}
			}
		})
	}

	if officialURL == "" {
		return ""
	}

	// Unwrap Google /url?q= redirect if present
	if strings.HasPrefix(officialURL, "/url?") {
		if u, err := url.Parse(officialURL); err == nil {
			officialURL = u.Query().Get("q")
		}
	}

	u, err := url.Parse(officialURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
