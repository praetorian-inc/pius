package ips

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/praetorian-inc/pius/pkg/plugins"
)

// IPResult is the local ASN database record containing an IP or CIDR target.
type IPResult struct {
	Query        string `json:"query"`
	StartAddress string `json:"start_address"`
	EndAddress   string `json:"end_address"`
	Number       int    `json:"number"`
	Country      string `json:"country"`
	Name         string `json:"name"`
}

// ipPlugin enriches IP and CIDR inputs from a caller-supplied local ASN database.
type ipPlugin struct {
	database *ipDatabase
}

type ipDatabase struct {
	path  string
	once  sync.Once
	zones []ipZone
	err   error
}

type ipZone struct {
	start   netip.Addr
	end     netip.Addr
	number  int
	country string
	name    string
}

var ipDatabases sync.Map

// NewIPPlugin builds the IP ASN plugin over databasePath. The database uses
// ip2asn's tab-separated start, end, ASN, country, and name format.
func NewIPPlugin(databasePath string) plugins.Plugin {
	database, _ := ipDatabases.LoadOrStore(databasePath, &ipDatabase{path: databasePath})
	return &ipPlugin{database: database.(*ipDatabase)}
}

func (p *ipPlugin) Name() string { return "ip" }
func (p *ipPlugin) Description() string {
	return "resolves IP and CIDR ASN metadata from a local database"
}
func (p *ipPlugin) Category() string { return "ip" }
func (p *ipPlugin) Phase() int       { return 0 }
func (p *ipPlugin) Mode() string     { return plugins.ModePassive }

func (p *ipPlugin) Accepts(input plugins.Input) bool {
	_, ok := ipTarget(input)
	return ok && p.database.path != ""
}

func (p *ipPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	query, ok := ipTarget(input)
	if !ok {
		return nil, fmt.Errorf("ip: expected exactly one IP or CIDR")
	}
	if p.database.path == "" {
		return nil, fmt.Errorf("ip: no ASN database path")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.database.once.Do(p.database.load)
	if p.database.err != nil {
		return nil, p.database.err
	}

	address := queryAddress(query)
	for _, zone := range p.database.zones {
		if address.Compare(zone.start) < 0 || address.Compare(zone.end) > 0 {
			continue
		}
		result := IPResult{
			Query:        query,
			StartAddress: zone.start.String(),
			EndAddress:   zone.end.String(),
			Number:       zone.number,
			Country:      zone.country,
			Name:         zone.name,
		}
		return []plugins.Finding{{
			Type:   plugins.FindingIPResult,
			Value:  query,
			Source: p.Name(),
			Data:   plugins.FindingData(result),
		}}, nil
	}
	return nil, nil
}

func (d *ipDatabase) load() {
	file, err := os.Open(d.path)
	if err != nil {
		d.err = fmt.Errorf("ip: open ASN database: %w", err)
		return
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		start, startErr := netip.ParseAddr(fields[0])
		end, endErr := netip.ParseAddr(fields[1])
		number, numberErr := strconv.Atoi(fields[2])
		if startErr != nil || endErr != nil || numberErr != nil {
			continue
		}
		d.zones = append(d.zones, ipZone{
			start:   start.Unmap(),
			end:     end.Unmap(),
			number:  number,
			country: fields[3],
			name:    strings.Join(fields[4:], " "),
		})
	}
	if err := scanner.Err(); err != nil {
		d.err = fmt.Errorf("ip: read ASN database: %w", err)
	}
}

func ipTarget(input plugins.Input) (string, bool) {
	target, ok := inputTarget(input)
	if !ok {
		return "", false
	}
	if input.IP != "" {
		address, err := netip.ParseAddr(target)
		if err != nil {
			return "", false
		}
		return address.Unmap().String(), true
	}
	prefix, err := netip.ParsePrefix(target)
	if err != nil {
		return "", false
	}
	return prefix.Masked().String(), true
}

func inputTarget(input plugins.Input) (string, bool) {
	if (input.IP == "") == (input.CIDR == "") {
		return "", false
	}
	if input.IP != "" {
		return input.IP, true
	}
	return input.CIDR, true
}

func queryAddress(query string) netip.Addr {
	if address, err := netip.ParseAddr(query); err == nil {
		return address.Unmap()
	}
	prefix, _ := netip.ParsePrefix(query)
	return prefix.Addr().Unmap()
}
