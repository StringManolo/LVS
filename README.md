# LVS - Local Vulnerability Scanner

LVS is a lightweight CLI tool to scan local projects for vulnerabilities.  
It currently supports auditing **npm packages** and mapping **CWE identifiers** to human-readable descriptions.

## Features

- Recursively scans directories for `package-lock.json`.
- Runs `npm audit` on each project to detect vulnerable packages.
- Maps CWE identifiers to descriptions using an internal dictionary.
- Pretty-prints vulnerabilities with colored output.
- Optional JSON output for automation or integration.
- Save results to a file with `-o / --output`.

## Installation

```bash
git clone https://github.com/StringManolo/lvs.git
cd lvs
npm install
npm link  # makes the `lvs` command available globally
```

### Usage
```bash
# Show help
lvs

# Scan current directory
lvs .

# Scan a specific directory
lvs /path/to/project

# Output JSON to console
lvs --json

# Save pretty output to a file
lvs -o report.txt

# Save JSON output to a file
lvs --json -o report.json /path/to/project
```

### Example Output
```
📂 Root: /home/user/project
🔹 Vulnerabilities found: 2

 1. ⚡ express <4.18.2 (score: 9.1)
    Source: node_modules/express
    Advisory: https://github.com/advisories/GHSA-xxxx
    CWE:
      • CWE-79 - Cross-site Scripting
      • CWE-22 - Path Traversal
    Fix: cd /home/user/project && npm audit fix express
```
