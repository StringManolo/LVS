import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

async function queryOSV(packageName, version) {
  const res = await fetch('https://api.osv.dev/v1/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      package: { name: packageName, ecosystem: 'PyPI' },
      version: version
    })
  });
  if (!res.ok) throw new Error(`OSV query failed for ${packageName}@${version}`);
  return res.json();
}

function parseRequirements(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n').filter(l => l && !l.startsWith('#'));
  return lines.map(line => {
    const [name, version] = line.split(/==|>=|<=|~=|>/);
    return { name: name.trim(), version: version?.trim() || 'latest' };
  });
}

export const scan = async (dir) => {
  const resolvedDir = path.resolve(dir);
  const reqFile = path.join(resolvedDir, 'requirements.txt');

  if (!fs.existsSync(reqFile)) {
    return [{ root: resolvedDir, vulnerabilities: [], amount: 0, scanner: 'python' }];
  }

  const packages = parseRequirements(reqFile);
  const vulnerabilities = [];

  for (const pkg of packages) {
    try {
      const data = await queryOSV(pkg.name, pkg.version);
      if (data.vulns && data.vulns.length > 0) {
        for (const vuln of data.vulns) {
          const aliases = vuln.aliases || [];
          const cveList = aliases.filter(a => a.startsWith('CVE-'));
          let githubRef = vuln.references?.find(r => r.url.includes('github'))?.url;
          if (!githubRef && vuln.references?.length) githubRef = vuln.references[0].url;

          const source = vuln.affected?.[0]?.package
            ? `${vuln.affected[0].package.ecosystem} - ${vuln.affected[0].package.name}`
            : `PyPI - ${pkg.name}`;

          const fixExists = !!vuln.affected?.some(a => a.ranges?.some(r => r.events?.some(e => e.fixed)));

          vulnerabilities.push({
            root: resolvedDir,
            name: pkg.name,
            version: pkg.version,
            score: vuln.database_specific?.severity || null,
            cve: cveList.length ? cveList : ['N/A'],
            remote: githubRef || 'N/A',
            details: vuln.details || vuln.summary || 'No details available',
            source,
            fix: fixExists,
            scanner: 'python'
          });
        }
      }
    } catch (err) {
      console.error(`Error querying ${pkg.name}@${pkg.version}:`, err.message || err);
    }
  }

  return [{ root: resolvedDir, vulnerabilities, amount: vulnerabilities.length, scanner: 'python' }];
};

export const printPretty = (scanResults) => {
  if (!Array.isArray(scanResults)) return;

  for (const res of scanResults) {
    const root = res.root || 'N/A';
    console.log(`${colors.bright}${colors.cyan}📂 Root: ${root}${colors.reset}`);
    console.log(`🔹 Vulnerabilities found: ${colors.yellow}${res.amount}${colors.reset}`);

    if (!res.vulnerabilities || res.vulnerabilities.length === 0) {
      console.log(`${colors.green}No vulnerabilities found.${colors.reset}`);
      console.log('\n' + '-'.repeat(60) + '\n');
      continue;
    }

    res.vulnerabilities.forEach((vuln, i) => {
      const severityColor =
        vuln.score === 'HIGH' ? colors.red :
        vuln.score === 'MODERATE' ? colors.yellow :
        colors.green;

      console.log(`\n ${i + 1}. ${severityColor}⚡ ${vuln.name} ${vuln.version} (score: ${vuln.score ?? 'N/A'})${colors.reset}`);
      console.log(`    Source: ${vuln.source}`);
      console.log(`    Advisory: ${vuln.remote}`);
      console.log(`    CVE:${vuln.cve.map(c => `\n      • ${c} - ${vuln.details}`).join('')}`);
      const fixCommand = vuln.fix ? `Update ${vuln.name} to a fixed version` : 'N/A';
      console.log(`    Fix: ${fixCommand}`);
    });

    console.log('\n' + '-'.repeat(60) + '\n');
  }
};

export default { scan, printPretty };

