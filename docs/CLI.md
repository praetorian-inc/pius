<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->

# pius CLI reference

Every command, alias and flag below is derived from the cobra command tree, not from prose.
Schema version 1, surface hash `sha256:23b50fcac7ff97d0349d714bd83216a1d67138d23f38b50d82935d48528b2c77`.

Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.

## Command index

| Command | Aliases | Description |
| --- | --- | --- |
| [`pius`](#pius) | *(none)* | Organizational asset discovery tool |
| [`pius list`](#pius-list) | *(none)* | List available plugins |
| [`pius run`](#pius-run) | *(none)* | Discover assets for an organization |

## `pius`

Organizational asset discovery tool

- Usage: `pius`
- Aliases: *(none)*
- Requires a subcommand

## `pius list`

List available plugins

- Usage: `pius list`
- Aliases: *(none)*

## `pius run`

Discover assets for an organization

- Usage: `pius run`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--asn` |  | string |  | Known ASN hint, e.g. AS12345 (optional) |
| `--cidr` |  | string |  | Known CIDR range, e.g. 8.8.8.0/24 (optional) |
| `--concurrency` |  | int | `5` | Max concurrent plugins |
| `--disable` |  | string |  | Comma-separated plugin blacklist |
| `--doh-deploy-gateways` |  | bool | `false` | Auto-deploy AWS API Gateways pointing to DoH servers |
| `--doh-gateways` |  | string |  | Comma-separated AWS API Gateway URLs for DoH |
| `--doh-servers` |  | string |  | Comma-separated DoH server URLs |
| `--doh-wordlist` |  | string |  | Path to subdomain wordlist for DoH enumeration (default: embedded) |
| `--domain` | `-d` | string |  | Known domain hint (optional) |
| `--ip` |  | string |  | Known IP address, e.g. 8.8.8.8 (optional) |
| `--mode` |  | string | `passive` | Plugin mode filter: passive\|active\|all |
| `--org` |  | string |  | Organization name to search (required) |
| `--output` | `-o` | string | `terminal` | Output format: terminal\|json\|ndjson |
| `--plugins` |  | string |  | Comma-separated plugin whitelist (default: all) |
