# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Website security scanner that automates client-side JavaScript dependency scanning. It crawls websites via sitemap, downloads JavaScript assets, and runs multiple security scans (vulnerability detection, dead domain detection, malware scanning).

## Common Commands

```bash
# Install dependencies
npm install

# Download JavaScript assets from a website (crawls sitemap)
npm run download-assets -- https://example.com

# Run vulnerability scan on downloaded assets
npx retire --path js_assets

# Check for dead/dangling domains (potential subdomain takeover)
node check-dead-domains.js

# Send email report (requires SMTP env vars)
node send-report.js

# Run full scan via Docker
docker compose build && docker compose up
```

## Architecture

### Core Scripts

- **download-assets.js** - Main crawler that:
  - Parses sitemap.xml to discover pages
  - Uses Puppeteer to visit pages and extract script URLs
  - Downloads JS files to `js_assets/` directory
  - Outputs `found_urls.json` (all URLs found) and `downloaded_scripts.json` (script metadata)
  - Writes scan metrics to `reports/scan-metadata.json`

- **check-dead-domains.js** - Dead domain scanner that:
  - Reads URLs from `found_urls.json` and scans JS files for embedded URLs
  - Performs DNS resolution on all discovered domains
  - Detects ENOTFOUND errors indicating potential subdomain takeover risks
  - Outputs `reports/dead-domains.json`

- **send-report.js** - Email report generator that:
  - Aggregates results from retire.js, ClamAV, and dead domain scans
  - Supports LLM-generated reports (OpenAI, DeepSeek, Gemini)
  - Falls back to template-based HTML if no LLM configured

- **run-scan.sh** - Docker entrypoint that orchestrates the full scan pipeline

### Environment Variables

URL filtering:
- `SKIP_URL_PREFIXES` - Comma-separated URL path prefixes to exclude
- `INCLUDE_URL_PREFIXES` - Exceptions to skip rules
- `SKIP_SCRIPT_DOMAINS` - Domains to skip when downloading scripts (defaults include Google, CDNs)

Email/LLM (for send-report.js):
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM`, `EMAIL_TO`
- `LLM_PROVIDER` (openai/deepseek/gemini/custom), `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL`

### Output Structure

```
js_assets/          # Downloaded JavaScript files
reports/
  retire-report.json    # Vulnerability scan results
  clamav-report.txt     # Malware scan results
  dead-domains.json     # Dead domain findings
  scan-metadata.json    # Scan statistics
found_urls.json         # All URLs discovered during crawl
downloaded_scripts.json # Metadata for downloaded scripts
```
