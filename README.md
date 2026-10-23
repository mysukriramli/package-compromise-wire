# 🚨 Package Compromise Wire

An autonomous, zero-maintenance data infrastructure running entirely on GitHub Actions. It tracks, parses, and permanently ledgers supply-chain compromises and malicious packages across PyPI, npm, and RubyGems.

## Data Feeds for Agents
Optimized for headless bots, vulnerability scanners, and LLMs.

- [`v1/active-alerts.json`](public/v1/active-alerts.json)
- [`v1/compromised-today.json`](public/v1/compromised-today.json)
- [`llms.txt`](public/llms.txt)
- `compromises.parquet` (Columnar database snapshot)

## Architecture
- **Ingest**: OSV Malicious Packages dataset
- **Database**: DuckDB (cached ephemerally)
- **Ledger**: Git-native append-only JSONL committed to `/data/history`
- **Delivery**: GitHub Pages (Fastly CDN)
