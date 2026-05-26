# Changelog

All notable changes to Pius will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `whoxy-reverse-whois` domain plugin — reverse WHOIS via Whoxy API with paginated lookup, stale-record filtering, and deduplication (Phase 0, passive, requires `WHOXY_API_KEY`)
- `builtwith` domain plugin — discovers related domains via shared analytics tracking codes passed through `Meta["analytics_ids"]` (Phase 3, passive, requires `BUILTWITH_API_KEY`)
- Credential mapping for `whoxy_api_key` and `builtwith_api_key` in the capability SDK bridge
- Meta key forwarding for `analytics_ids` to support cross-phase data passing to BuiltWith plugin
