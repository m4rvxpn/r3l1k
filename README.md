# r3l1k
r3l1k Vulnerability Report Automation with AI and Ghostwriter is a Python command line utility that consolidates Nessus scan files, deduplicates vulnerabilities by plugin identifier, enriches them with technical AI generated content, and can optionally sync normalized findings into Ghostwriter while keeping asset identifiers local and never sending host or port information to the AI component.[1]

## Project name

r3l1k Vulnerability Report Automation with AI and Ghostwriter[1]

## Description

r3l1k parses one or more Nessus scan exports and builds a unified vulnerability catalog keyed by plugin identifier, aggregating shared properties such as severity, scores, description, solution, references, exploit metadata, and a bounded snippet of plugin output. During this process, instance level data such as IP addresses, protocols, and ports are tracked separately and used only for CSV export and Ghostwriter affected entities, and are not provided to the AI service, so asset context remains local to the environment running the tool.[1]

The AI enhancement pipeline uses Gemini clients to generate consistent technical descriptions and impact statements per unique vulnerability, with key rotation, rate limiting, and safe fallbacks when AI is disabled or unavailable. Ghostwriter integration is handled via a small client wrapper that authenticates with a token, formats text into simple HTML, and inserts findings through a GraphQL mutation for streamlined reporting workflows.[1]

## Features

- Parse multiple Nessus files and consolidate vulnerabilities by plugin identifier into a single catalog.[1]
- Aggregate affected hosts and ports per vulnerability instance for downstream reporting and Ghostwriter mapping.[1]
- Extract severity, CVSS scores and vectors, solutions, references, exploit availability, exploit code maturity, and exploitability ease from Nessus metadata.[1]
- Enhance each unique vulnerability with AI generated technical description and impact, with deterministic fallbacks when AI is not used.[1]
- Maintain a strict separation between vulnerability level data and asset level instance data, ensuring that host addresses and ports are never passed to the AI component.[1]
- Integrate with Ghostwriter to create normalized findings with formatted descriptions, impact, references, and affected entities through GraphQL.[1]
- Handle rate limiting, key validation, and key rotation for Gemini, and display terminal feedback such as banners and spinner animations during long operations.[1]

## Architecture and workflow

r3l1k first parses each Nessus file using an XML parser and builds two main mappings. The vulnerability mapping stores plugin centric data such as name, severity, description, CVSS information, solution, references, plugin output, and exploit metadata, while the instance mapping tracks which hosts and ports are affected for each plugin across files.[1]

AI enhancement is applied once per unique plugin identifier using only vulnerability level fields and a truncated plugin output snippet to generate JSON containing a refined name, description, and impact with a purely technical focus. The tool then merges this enhanced content back into the catalog, keeping the instance mapping untouched and strictly local, and writes consolidated CSV files and optional Ghostwriter findings.[1]

## Requirements

r3l1k is written in Python and uses standard libraries plus a few external packages.[1]

- lxml for Nessus XML parsing[1]
- google genai for Gemini based AI enhancement[1]
- tldextract for domain extraction in references[1]
- requests for HTTP interactions, including Ghostwriter API calls and resolving redirected links in references[1]
- python dotenv for loading configuration from an environment file when available[1]

Install the dependencies with a command similar to:

```bash
pip install lxml google-genai tldextract requests python-dotenv
```


## Environment configuration

r3l1k supports configuration through environment variables, typically loaded from a dotenv file if the helper is installed.[1]

- GEMINI_API_KEYS  
  - Comma separated Gemini API keys used for AI enhancement with automatic rotation when quotas are hit.[1]
- GHOSTWRITER_API_KEY  
  - Token used for authenticating to the Ghostwriter instance.[1]
- GHOSTWRITER_URL  
  - Base URL of the Ghostwriter GraphQL endpoint.[1]

If GEMINI_API_KEYS is not provided or AI is explicitly disabled with a flag, r3l1k runs in a non AI mode and generates deterministic descriptions and impact statements directly from Nessus data. If Ghostwriter credentials are not set, the tool simply skips the integration step and focuses on local CSV outputs.[1]

## Usage

A typical invocation of r3l1k looks like this.[1]

```bash
python relik.py \
  --company "Your Company" \
  --report-id 123 \
  --output-dir ./output \
  scans/*.nessus
```


Common command line options include.[1]

- company  
  - Name of the organization performing the assessment, injected into generated descriptions.[1]
- report id  
  - Identifier used when creating Ghostwriter findings to associate them with a specific report.[1]
- output dir  
  - Directory where CSV outputs and related artifacts are written.[1]
- disable ai  
  - Flag to explicitly turn off AI enhancement, even if GEMINI_API_KEYS is configured.[1]
- verify ssl  
  - Option to disable TLS verification for Ghostwriter connections in lab environments.[1]

## Output

r3l1k produces CSV files containing consolidated vulnerability and instance data. One CSV focuses on vulnerability definitions with fields like plugin identifier, technical name, severity, scores, vectors, solutions, references, and AI enhanced description and impact where available, while another captures instance level rows with source file, IP address, protocol, port, and associated vulnerability metadata.[1]

When Ghostwriter integration is enabled, the tool creates findings in the platform using structured fields mapped from the catalog. These findings include HTML formatted descriptions and impact, severity mapped to the numeric scale expected by Ghostwriter, CVSS information, references, and a list of affected entities derived from host and port mappings.[1]

## Privacy and data handling

r3l1k is designed with a clear separation between vulnerability level data and asset level data. The AI component only receives vulnerability fields such as name, severity, description, CVSS score, exploit flags, and a trimmed snippet of plugin output, and does not receive any host addresses, ports, or other asset identifiers.[1]

All asset specific context, including IP addresses, protocols, ports, and per instance relationships between hosts and plugin identifiers, is processed locally inside r3l1k for CSV generation and Ghostwriter affected entity construction. This approach ensures that AI calls operate on a zero knowledge view of asset inventory, and external services never see which systems are affected.[1]

## FAQ

### Does r3l1k send host or asset data to the AI service

No, r3l1k never sends asset identifiers such as IP addresses, hostnames, or ports to the AI component. Only vulnerability level metadata and a bounded plugin output snippet are used in AI prompts, and instance mapping remains entirely local to the process.[1]

### Can r3l1k run without AI

Yes, r3l1k can run without AI by omitting GEMINI_API_KEYS or using the disable ai flag. In this mode, it still parses Nessus files, consolidates vulnerabilities, and generates CSV outputs with deterministic descriptions and impact text.[1]

### Is Ghostwriter required to use r3l1k

No, Ghostwriter is optional. If GHOSTWRITER_URL and GHOSTWRITER_API_KEY are not configured, r3l1k skips the integration step and focuses entirely on local CSV outputs.[1]

### What formats of Nessus output are supported

r3l1k expects the standard Nessus XML export format with reports, hosts, report items, and tags such as host ip, severity, description, solution, CVSS fields, references, and exploit metadata. These elements are used to build the vulnerability catalog and instance mappings.[1]

### How does r3l1k handle multiple Nessus files from the same engagement

The tool parses each file and merges vulnerabilities based on plugin identifier, so the same issue found across multiple scans is represented once in the catalog with aggregated host and port data. This deduplication reduces report noise and ensures a single AI enhancement per unique vulnerability.[1]

## Troubleshooting

### AI enhancement is not running

- Check that GEMINI_API_KEYS is set and contains at least one valid key in the expected format.[1]
- Ensure the required AI client library is installed and importable.[1]
- Confirm that the disable ai flag is not set in your command line invocation.[1]
- Review terminal output for messages about invalid keys, missing libraries, or quota issues.[1]

### AI errors or quota exceeded messages

- r3l1k validates keys at startup and can rotate between multiple keys when quotas are hit.[1]
- If all keys are exhausted, the tool falls back to deterministic descriptions and impact text while continuing processing.[1]
- Consider adding more keys to GEMINI_API_KEYS or reducing the number of unique vulnerabilities processed per run in high volume scenarios.[1]

### Ghostwriter integration is failing

- Verify that GHOSTWRITER_URL points to the correct GraphQL endpoint and is reachable from the environment running r3l1k.[1]
- Confirm that GHOSTWRITER_API_KEY is valid and has permission to insert reported findings.[1]
- Check SSL verification settings if using self signed certificates, and adjust the verify ssl option if needed in lab deployments.[1]

### CSV files are empty or incomplete

- Ensure that the input Nessus files contain non informational findings with severity greater than zero, as informational entries may be skipped.[1]
- Review terminal messages for XML parsing errors or issues reading specific files, and rerun with a reduced set of known good inputs.[1]

### References or domains look incorrect

- r3l1k attempts to resolve certain Nessus redirect links using HTTP requests and extract clean domains for readability.[1]
- If outbound HTTP is blocked or a link cannot be resolved, the original reference is used as a fallback, which can lead to less normalized reference text.[1]

[1](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/46062702/e3b85dc2-794f-45b7-9e43-c39418517d97/relik.py)
