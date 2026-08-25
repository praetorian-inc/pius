package cidrs

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/praetorian-inc/pius/pkg/client"
	"github.com/praetorian-inc/pius/pkg/lib/strutil"
	"github.com/praetorian-inc/pius/pkg/plugins"
)

const (
	confReverseRIRHandle        = 60
	confReverseRIROrgSimilarity = 25
	minReverseRIROrgSimilarity  = 0.5
)

func init() {
	plugins.Register("reverse-rir", func() plugins.Plugin {
		return NewReverseRIRPlugin(client.New())
	})
}

// NewReverseRIRPlugin builds the plugin around a caller-supplied client, for
// embedders that must route pius egress through their own transport rather than
// the package default. A nil client takes the default, which is what the
// self-registering plugin uses.
func NewReverseRIRPlugin(c *client.Client) *ReverseRIRPlugin {
	if c == nil {
		c = client.New()
	}
	return &ReverseRIRPlugin{client: c}
}

// ReverseRIRPlugin discovers RIR org handles from company names.
// Queries ARIN, RIPE, APNIC, AFRINIC, and LACNIC WHOIS/RDAP APIs.
// Phase 1 plugin: emits FindingCIDRHandle findings consumed by Phase 2 and
// FindingRIRResult findings carrying the registry records behind those handles.
type ReverseRIRPlugin struct {
	client *client.Client
}

func (p *ReverseRIRPlugin) Name() string { return "reverse-rir" }
func (p *ReverseRIRPlugin) Description() string {
	return "Reverse RIR lookup: discovers org handles from company name via ARIN/RIPE/APNIC/AFRINIC/LACNIC"
}
func (p *ReverseRIRPlugin) Category() string { return "cidr" }
func (p *ReverseRIRPlugin) Phase() int       { return 1 }
func (p *ReverseRIRPlugin) Mode() string     { return plugins.ModePassive }

func (p *ReverseRIRPlugin) Accepts(input plugins.Input) bool {
	return strings.TrimSpace(input.OrgName) != ""
}

func (p *ReverseRIRPlugin) Run(ctx context.Context, input plugins.Input) ([]plugins.Finding, error) {
	var findings []plugins.Finding

	arinFindings, err := p.queryARIN(ctx, input.OrgName)
	if err != nil {
		slog.Warn("ARIN query failed", "plugin", "reverse-rir", "org", input.OrgName, "error", err)
	}
	findings = append(findings, arinFindings...)

	ripeFindings, err := p.queryRIPE(ctx, input.OrgName)
	if err != nil {
		slog.Warn("RIPE query failed", "plugin", "reverse-rir", "org", input.OrgName, "error", err)
	}
	findings = append(findings, ripeFindings...)

	apnicFindings, err := p.queryAPNIC(ctx, input.OrgName)
	if err != nil {
		slog.Warn("APNIC query failed", "plugin", "reverse-rir", "org", input.OrgName, "error", err)
	}
	findings = append(findings, apnicFindings...)

	afrinicFindings, err := p.queryAFRINIC(ctx, input.OrgName)
	if err != nil {
		slog.Warn("AFRINIC query failed", "plugin", "reverse-rir", "org", input.OrgName, "error", err)
	}
	findings = append(findings, afrinicFindings...)

	lacnicFindings, err := p.queryLACNIC(ctx, input.OrgName)
	if err != nil {
		slog.Warn("LACNIC query failed", "plugin", "reverse-rir", "org", input.OrgName, "error", err)
	}
	findings = append(findings, lacnicFindings...)

	return findings, nil
}

// newReverseRIRFinding builds the handle and registry-result findings from a
// fully assembled registry record. Unusable records produce no findings.
func newReverseRIRFinding(database string, data ReverseRIRFindingData) []plugins.Finding {
	data.Handle = strings.TrimSpace(data.Handle)
	data.Name = strings.TrimSpace(data.Name)
	data.QueriedOrganization = strings.TrimSpace(data.QueriedOrganization)

	if data.Handle == "" || data.QueriedOrganization == "" || !resolvableRegistry(data.Registry) {
		slog.Debug("reverse-rir: dropping unusable handle",
			"handle", data.Handle,
			"org", data.QueriedOrganization,
			"registry", data.Registry,
			"database", database,
		)
		return nil
	}

	handleFinding := plugins.Finding{
		Type:   plugins.FindingCIDRHandle,
		Value:  data.Handle,
		Source: "reverse-rir",
		Data: map[string]any{
			"registry": data.Registry,
			"org":      data.Name,
		},
	}
	plugins.AddConfidence(&handleFinding, confReverseRIRHandle, fmt.Sprintf(
		"%s returned organization handle %q for organization search %q",
		database, data.Handle, data.QueriedOrganization,
	))

	if similarity := strutil.TokenSimilarity(data.QueriedOrganization, data.Name); similarity >= minReverseRIROrgSimilarity {
		plugins.AddConfidence(&handleFinding, confReverseRIROrgSimilarity, fmt.Sprintf(
			"RIR organization name %q matches the queried organization %q",
			data.Name, data.QueriedOrganization,
		))
	}

	resultFinding := plugins.Finding{
		Type:        plugins.FindingRIRResult,
		Value:       data.Handle,
		Source:      handleFinding.Source,
		Confidences: slices.Clone(handleFinding.Confidences),
		Data:        plugins.FindingData(data),
	}
	return []plugins.Finding{handleFinding, resultFinding}
}

// ReverseRIRFindingData is the common envelope emitted for every registry
// record that produced a CIDR handle. Record preserves the registry-native JSON.
type ReverseRIRFindingData struct {
	Registry            string          `json:"registry"`
	Handle              string          `json:"handle"`
	Name                string          `json:"name,omitempty"`
	QueriedOrganization string          `json:"queriedOrganization,omitempty"`
	Street              []string        `json:"street,omitempty"`
	City                string          `json:"city,omitempty"`
	StateProvince       string          `json:"stateProvince,omitempty"`
	PostalCode          string          `json:"postalCode,omitempty"`
	Country             string          `json:"country,omitempty"`
	RegistrationDate    string          `json:"registrationDate,omitempty"`
	LastUpdated         string          `json:"lastUpdated,omitempty"`
	Comments            []string        `json:"comments,omitempty"`
	SourceURL           string          `json:"sourceUrl,omitempty"`
	Record              json.RawMessage `json:"record"`
}

func newRPSLResultData(
	registry, handle, queriedOrganization, sourceURL string,
	attributes rpslAttributes,
	record json.RawMessage,
) ReverseRIRFindingData {
	return ReverseRIRFindingData{
		Registry:            registry,
		Handle:              handle,
		Name:                attributes.Name,
		QueriedOrganization: queriedOrganization,
		Street:              attributes.Street,
		Country:             attributes.Country,
		RegistrationDate:    attributes.RegistrationDate,
		LastUpdated:         attributes.LastUpdated,
		Comments:            attributes.Comments,
		SourceURL:           sourceURL,
		Record:              record,
	}
}

type rpslAttributes struct {
	Name             string
	Street           []string
	Country          string
	RegistrationDate string
	LastUpdated      string
	Comments         []string
}

func (attributes *rpslAttributes) add(name string, values ...string) {
	switch name {
	case "org-name":
		attributes.Name = cmp.Or(attributes.Name, first(values))
	case "address":
		attributes.Street = append(attributes.Street, values...)
	case "country":
		attributes.Country = cmp.Or(attributes.Country, first(values))
	case "created":
		attributes.RegistrationDate = cmp.Or(attributes.RegistrationDate, first(values))
	case "last-modified":
		attributes.LastUpdated = cmp.Or(attributes.LastUpdated, first(values))
	case "remarks":
		attributes.Comments = append(attributes.Comments, values...)
	}
}

func applyRDAPResultData(
	data *ReverseRIRFindingData,
	entity RdapEntity,
	record json.RawMessage,
) {
	data.Record = record
	data.SourceURL = cmp.Or(entity.selfLink(), data.SourceURL)
	data.RegistrationDate = cmp.Or(
		entity.eventDate("registration"), data.RegistrationDate)
	data.LastUpdated = cmp.Or(
		entity.eventDate("last changed"), data.LastUpdated)
	for _, remark := range entity.Remarks {
		data.Comments = append(data.Comments, remark.Description...)
	}

	for _, property := range entity.VCard.Properties {
		switch property.Name {
		case "fn":
			data.Name = cmp.Or(property.stringValue(), data.Name)
		case "adr":
			applyRDAPAddress(data, property)
		case "note":
			if comment := property.stringValue(); comment != "" {
				data.Comments = append(data.Comments, comment)
			}
		}
	}
}

func applyRDAPAddress(data *ReverseRIRFindingData, property rdapVCardProperty) {
	values := property.stringValues()
	if len(values) >= 7 {
		data.Street = appendNonempty(data.Street, values[2])
		data.City = cmp.Or(values[3], data.City)
		data.StateProvince = cmp.Or(values[4], data.StateProvince)
		data.PostalCode = cmp.Or(values[5], data.PostalCode)
		data.Country = cmp.Or(values[6], data.Country)
	}
	if len(data.Street) > 0 {
		return
	}

	lines := nonemptyLines(property.Parameters.Label)
	if len(lines) == 0 {
		return
	}
	data.Street = append(data.Street, lines[0])
	if len(lines) > 1 && data.City == "" {
		data.City = lines[1]
	}
}

type RdapEntity struct {
	Handle  string       `json:"handle"`
	VCard   rdapVCard    `json:"vcardArray"`
	Events  []rdapEvent  `json:"events"`
	Remarks []rdapRemark `json:"remarks"`
	Links   []rdapLink   `json:"links"`
}

func (entity RdapEntity) eventDate(action string) string {
	for _, event := range entity.Events {
		if event.Action == action {
			return event.Date
		}
	}
	return ""
}

func (entity RdapEntity) selfLink() string {
	for _, link := range entity.Links {
		if link.Relation == "self" {
			return link.Href
		}
	}
	return ""
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapRemark struct {
	Description []string `json:"description"`
}

type rdapLink struct {
	Relation string `json:"rel"`
	Href     string `json:"href"`
}

type rdapVCard struct {
	Properties []rdapVCardProperty
}

func (vcard *rdapVCard) UnmarshalJSON(data []byte) error {
	var tuple []json.RawMessage
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) < 2 {
		return nil
	}

	var rawProperties []json.RawMessage
	if err := json.Unmarshal(tuple[1], &rawProperties); err != nil {
		return err
	}
	for _, rawProperty := range rawProperties {
		var property rdapVCardProperty
		if property.unmarshalJSON(rawProperty) == nil {
			vcard.Properties = append(vcard.Properties, property)
		}
	}
	return nil
}

type rdapVCardProperty struct {
	Name       string
	Parameters rdapVCardParameters
	Text       string
	Address    []string
}

func (property *rdapVCardProperty) unmarshalJSON(data []byte) error {
	var tuple []json.RawMessage
	if err := json.Unmarshal(data, &tuple); err != nil {
		return err
	}
	if len(tuple) < 4 {
		return fmt.Errorf("RDAP vCard property has %d fields", len(tuple))
	}
	if err := json.Unmarshal(tuple[0], &property.Name); err != nil {
		return err
	}
	if err := json.Unmarshal(tuple[1], &property.Parameters); err != nil {
		return err
	}
	if property.Name == "adr" {
		property.Address = rdapStrings(tuple[3])
		return nil
	}
	_ = json.Unmarshal(tuple[3], &property.Text)
	return nil
}

func (property rdapVCardProperty) stringValue() string {
	return property.Text
}

func (property rdapVCardProperty) stringValues() []string {
	return property.Address
}

func rdapStrings(data json.RawMessage) []string {
	var rawValues []json.RawMessage
	if json.Unmarshal(data, &rawValues) != nil {
		return nil
	}
	values := make([]string, len(rawValues))
	for i, rawValue := range rawValues {
		_ = json.Unmarshal(rawValue, &values[i])
	}
	return values
}

type rdapVCardParameters struct {
	Label string `json:"label"`
}

type nativeRecord[T any] struct {
	Value T
	Raw   json.RawMessage
}

func (record *nativeRecord[T]) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &record.Value); err != nil {
		return err
	}
	record.Raw = slices.Clone(data)
	return nil
}

func jsonRecord[T any](value T) json.RawMessage {
	record, _ := json.Marshal(value)
	return record
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func appendNonempty(values []string, value string) []string {
	if value == "" || slices.Contains(values, value) {
		return values
	}
	return append(values, value)
}

func nonemptyLines(value string) []string {
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

var knownRIRs = []string{
	"arin", "lacnic", "apnic", "afrinic", "ripe",
}

// resolvableRegistry reports whether a phase-two plugin in this package can
// resolve a handle at one of the five regional internet registries.
func resolvableRegistry(registry string) bool {
	return slices.Contains(knownRIRs, strings.ToLower(registry))
}
