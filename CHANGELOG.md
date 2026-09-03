# Changelog

All notable changes to Pius will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `whoisfreaks-reverse-whois` domain plugin — reverse WHOIS via WhoisFreaks API with exact company/owner/email pivots, org-name owner dual-index queries, legal-suffix punctuation aliases, pagination, and stale-record filtering (Phase 0, passive, requires `WHOISFREAKS_API_KEY`)
- Legal-suffix punctuation aliases for reverse-WHOIS org queries (`L.P.` also searches `LP`) shared by ViewDNS, Whoxy, and WhoisFreaks
- `whoxy-reverse-whois` domain plugin — reverse WHOIS via Whoxy API with paginated lookup, stale-record filtering, and deduplication (Phase 0, passive, requires `WHOXY_API_KEY`)
- `builtwith` domain plugin — discovers related domains via shared analytics tracking codes passed through `Meta["analytics_ids"]` (Phase 3, passive, requires `BUILTWITH_API_KEY`)
- Credential mapping for `whoxy_api_key` and `builtwith_api_key` in the capability SDK bridge
- Meta key forwarding for `analytics_ids` to support cross-phase data passing to BuiltWith plugin
