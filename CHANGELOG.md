# Changelog

All notable changes to Pius will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `whoxy-reverse-whois` domain plugin — reverse WHOIS via Whoxy API with paginated lookup, stale-record filtering, and deduplication (Phase 0, passive, requires `WHOXY_API_KEY`)
- `builtwith` domain plugin — discovers related domains via shared analytics tracking codes passed through `Meta["analytics_ids"]` (Phase 3, passive, requires `BUILTWITH_API_KEY`)
- Credential mapping for `whoxy_api_key` and `builtwith_api_key` in the capability SDK bridge
- Meta key forwarding for `analytics_ids` to support cross-phase data passing to BuiltWith plugin
- `pkg/whoisfreaks` SSL certificate client — single-domain WhoisFreaks `ssl/live` lookups (leaf + optional chain; parsed fields — subject/issuer, SANs, key usages, OCSP responders, public-key size parsed from the vendor's unit-suffixed string, and validity dates tolerant of the vendor's unpadded-day format — plus `authenticationType` and raw PEM), header-driven per-category rate limiting, and credit accounting (`+1 per 2 chain certs`, capped) (OFFSEC-2444)
- Case-insensitive whole-key redaction in `pkg/client` `sanitizeURL` — covers camelCase `apiKey` and other mixed-case credential params (OFFSEC-2444)
