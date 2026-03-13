package cidrs

import (
	"bufio"
	"os"
	"strings"
)

// parseRPSLInetnums parses an RPSL database file and returns IP ranges for the given handles.
// Used by both APNIC and AFRINIC plugins.
func parseRPSLInetnums(filePath string, handles []string) (map[string][]ipRange, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Normalize handles for matching
	handleSet := make(map[string]bool)
	for _, h := range handles {
		handleSet[strings.TrimSpace(strings.ToUpper(h))] = true
	}

	results := make(map[string][]ipRange)
	scanner := bufio.NewScanner(f)

	var currentInetnum, currentOrg, currentNetname string
	var inetnumStart, inetnumEnd string

	for scanner.Scan() {
		line := scanner.Text()

		// RPSL records are separated by blank lines
		if strings.TrimSpace(line) == "" {
			// End of record - check if it matches our handles
			if currentOrg != "" && handleSet[strings.ToUpper(currentOrg)] && inetnumStart != "" && inetnumEnd != "" {
				results[currentOrg] = append(results[currentOrg], ipRange{
					start:   inetnumStart,
					end:     inetnumEnd,
					netname: currentNetname,
				})
			}
			// Reset for next record
			currentInetnum, currentOrg, currentNetname = "", "", ""
			inetnumStart, inetnumEnd = "", ""
			continue
		}

		// Parse RPSL fields
		if strings.HasPrefix(line, "inetnum:") {
			currentInetnum = strings.TrimSpace(strings.TrimPrefix(line, "inetnum:"))
			// Parse range "192.168.0.0 - 192.168.255.255"
			parts := strings.Split(currentInetnum, "-")
			if len(parts) == 2 {
				inetnumStart = strings.TrimSpace(parts[0])
				inetnumEnd = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "org:") {
			currentOrg = strings.TrimSpace(strings.TrimPrefix(line, "org:"))
		} else if strings.HasPrefix(line, "netname:") {
			currentNetname = strings.TrimSpace(strings.TrimPrefix(line, "netname:"))
		}
	}

	return results, scanner.Err()
}

// ipRange represents an IP address range from an RPSL inetnum record.
type ipRange struct {
	start   string
	end     string
	netname string
}
