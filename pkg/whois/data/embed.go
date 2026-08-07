package data

import (
	"embed"
	"strings"
)

//go:embed *.txt
var fs embed.FS

var (
	NoisyPrefixes          []string
	NoisySuffixes          []string
	PrivacyOrgs            map[string]bool
	PrivacyNames           map[string]bool
	LegalSuffixes          map[string]bool
	RedactionMarkers       []string
	RegistryArtifacts      map[string][]string // ccTLD suffix → registry operator strings
)

func init() {
	NoisyPrefixes = loadSlice("prefixes.txt")
	NoisySuffixes = loadSlice("suffixes.txt")
	PrivacyOrgs = loadSet("privacy_orgs.txt")
	PrivacyNames = loadSet("privacy_names.txt")
	LegalSuffixes = loadSet("legal_suffixes.txt")
	RedactionMarkers = loadSlice("redaction_markers.txt")
	RegistryArtifacts = loadRegistryArtifacts("registry_artifacts.txt")
}

func loadSlice(name string) []string {
	raw, err := fs.ReadFile(name)
	if err != nil {
		panic("whois/data: missing embedded file: " + name)
	}
	var out []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, strings.ToLower(line))
		}
	}
	return out
}

func loadSet(name string) map[string]bool {
	lines := loadSlice(name)
	m := make(map[string]bool, len(lines))
	for _, line := range lines {
		m[line] = true
	}
	return m
}

func loadRegistryArtifacts(name string) map[string][]string {
	raw, err := fs.ReadFile(name)
	if err != nil {
		panic("whois/data: missing embedded file: " + name)
	}
	m := make(map[string][]string)
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		suffix := strings.TrimSpace(parts[0])
		value := strings.ToLower(strings.TrimSpace(parts[1]))
		m[suffix] = append(m[suffix], value)
	}
	return m
}
