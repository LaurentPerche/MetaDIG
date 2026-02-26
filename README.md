# MetaDIG

MetaDIG is a small command line tool that enumerates subdomains for an apex
domain via the SecurityTrails API, then resolves each subdomain to show its
DNS chain with a focus on CNAME targets and A records.

It is designed for quick infrastructure mapping and vendor fingerprinting
(CDN, WAF, PaaS), with colored keyword highlighting and a simple frequency
summary at the end.

## What it does

Given an apex domain (example: `accor.com`), MetaDIG:

1. Calls SecurityTrails to discover subdomains.
2. Runs `dig` on each subdomain to capture:
   • CNAME (when present)
   • A records and TTLs
3. Optionally enriches A record IPs using Team Cymru WHOIS
   to show ASN, country code, and AS name.
4. Highlights common provider keywords in the output.
5. Prints a summary:
   • total subdomain count processed
   • keyword frequency counts

## Example output

```
press.accor.com                          CNAME pressaccorcom.epresspack.link. TTL 900 A 54.36.54.250
group.accor.com                          CNAME iv78fgv.ng.impervadns.net. TTL 30 A 45.60.159.180
sofitel.accor.com                        CNAME i3tf7zxzobp.8tx293jn7e.ioriveredge.net. TTL 20 A 110.164.21.130 ; TTL 20 A 110.164.21.8

Subdomains count: 555
cloudfront   12
impervadns   45
...
```

## Requirements

macOS or Linux recommended.

### Tools

• Python 3.10+  
• `dig` (usually provided by `bind` tools)  
• `whois` (optional, for ASN enrichment)

On macOS:

```bash
brew install whois
```

`dig` is usually available, but if not:

```bash
brew install bind
```

## Setup

### SecurityTrails API key

Export your API key as an environment variable:

```bash
export SECURITYTRAILS_APIKEY="YOUR_KEY"
```

## Usage

Run against an apex domain:

```bash
python3 st_subdomains_cname_a.py accor.com
```

Useful flags:

```bash
python3 st_subdomains_cname_a.py accor.com --children-only
python3 st_subdomains_cname_a.py accor.com --include-inactive
python3 st_subdomains_cname_a.py accor.com --limit 200
python3 st_subdomains_cname_a.py accor.com --workers 40
python3 st_subdomains_cname_a.py accor.com --no-asn
```

### Notes about performance

The script uses a thread pool to resolve many subdomains in parallel.
If you run into rate limiting, timeouts, or your DNS resolver gets grumpy,
reduce concurrency:

```bash
python3 st_subdomains_cname_a.py accor.com --workers 10
```

## Color highlighting

MetaDIG highlights specific keywords to make common infrastructure patterns
pop visually.

Red:

• cloudfront  
• impervadns  
• edgecastcdn  
• fastly  
• ioriveredge  
• edgekey  
• cloudflare  

Blue:

• vercel-dns  
• adobeaemcloud  
• azurewebsites  
• amazonaws  

Yellow:

• api  

At the end of the run, MetaDIG prints keyword frequencies across the output.

## Project structure

```
.
├── st_subdomains_cname_a.py
└── README.md
```

## Security and data handling

• The script only queries:
  • SecurityTrails API for subdomain enumeration
  • DNS resolvers via `dig`
  • Team Cymru WHOIS (optional) for ASN enrichment

• No results are uploaded anywhere else.
• Be mindful of your organization’s policies before scanning third party
  domains.

## Troubleshooting

### “Missing API key”

Set the environment variable or pass `--api-key`:

```bash
export SECURITYTRAILS_APIKEY="YOUR_KEY"
python3 st_subdomains_cname_a.py example.com
```

### “whois: command not found”

Install whois:

```bash
brew install whois
```

### Slow or inconsistent results

Try fewer workers:

```bash
python3 st_subdomains_cname_a.py example.com --workers 10
```

## Roadmap ideas

• Output to JSON or CSV  
• Save raw `dig` output per subdomain  
• Add `AAAA` and `MX` modes  
• Smarter keyword counting (per record type and per vendor category)  
• Resolver selection and retry logic

## Disclaimer

This tool is intended for legitimate security and infrastructure analysis.
Use it responsibly and only against domains you are authorized to assess.
