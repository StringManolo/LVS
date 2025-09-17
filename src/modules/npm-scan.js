import { exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import util from 'util';
import { cweDescriptions } from './cwe-descriptions.js';

const execAsync = util.promisify(exec);

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

const findPackageLocks = (dir) => {
  const results = [];
  const stack = [path.resolve(dir)];

  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules') continue;
        stack.push(full);
      } else if (entry.isFile() && entry.name === 'package-lock.json') {
        results.push(full);
      }
    }
  }

  return results;
};

const parseAudit = (auditJson, rootDir) => {
  const vulnerabilities = [];
  const vulns = auditJson.vulnerabilities || {};
  let amount = 0;

  for (const [pkgName, data] of Object.entries(vulns)) {
    amount++;
    const via = Array.isArray(data.via) ? data.via : [data.via];

    for (const v of via) {
      if (typeof v === 'object') {
        vulnerabilities.push({
          root: rootDir,
          source: (data.nodes && data.nodes[0]) || null,
          remote: v.url || null,
          cwe: v.cwe || null,
          score: v.cvss?.score ?? null,
          fix: !!data.fixAvailable,
          name: pkgName,
          version: v.range || data.range || null,
        });
      }
    }
  }

  return { vulnerabilities, amount, scanner: 'npm' };
};

export const scanNpm = async (dir) => {
  const locks = findPackageLocks(dir);
  const allResults = [];

  for (const lockPath of locks) {
    const rootDir = path.dirname(lockPath);
    console.log(`🔹 Auditing: ${rootDir}`);

    try {
      const { stdout } = await execAsync('npm audit --json', {
        cwd: rootDir,
        env: process.env,
        shell: true,
        maxBuffer: 10 * 1024 * 1024,
      });

      const auditJson = JSON.parse(stdout);
      allResults.push(parseAudit(auditJson, rootDir));
    } catch (err) {
      if (err && err.stdout) {
        try {
          const auditJson = JSON.parse(err.stdout);
          allResults.push(parseAudit(auditJson, rootDir));
        } catch (parseErr) {
          console.error(`Error parsing JSON from ${rootDir}:`, parseErr);
        }
      } else {
        console.error(`Error auditing ${rootDir}:`, err?.message || err);
      }
    }
  }

  return allResults;
};

export const printPretty = (scanResults) => {
  if (!Array.isArray(scanResults)) return;

  for (const res of scanResults) {
    const root = res?.vulnerabilities?.[0]?.root || res.root || 'N/A';
    console.log(`${colors.bright}${colors.cyan}📂 Root: ${root}${colors.reset}`);
    console.log(`🔹 Vulnerabilities found: ${colors.yellow}${res.amount}${colors.reset}`);

    if (!res.vulnerabilities || res.vulnerabilities.length === 0) {
      console.log(`${colors.green}No vulnerabilities found.${colors.reset}`);
      console.log('\n' + '-'.repeat(60) + '\n');
      continue;
    }

    res.vulnerabilities.forEach((vuln, i) => {
      const score = vuln.score ?? 0;
      const severityColor =
        score >= 9 ? colors.red : score >= 7 ? colors.yellow : colors.green;

      console.log(`\n ${i + 1}. ${severityColor}⚡ ${vuln.name} ${vuln.version || ''} (score: ${vuln.score ?? 'N/A'})${colors.reset}`);
      console.log(`    Source: ${vuln.source ?? 'N/A'}`);
      console.log(`    Advisory: ${vuln.remote ?? 'N/A'}`);

      let cweOut = 'N/A';
      if (vuln.cwe) {
        if (Array.isArray(vuln.cwe)) {
          cweOut = vuln.cwe
            .map(c => `\n      • ${c} - ${cweDescriptions[c] || 'Description unavailable'}`)
            .join('');
        } else {
          cweOut = `\n      • ${vuln.cwe} - ${cweDescriptions[vuln.cwe] || 'Description unavailable'}`;
        }
      }
      console.log(`    CWE:${cweOut}`);

      const fixCommand = vuln.fix ? `cd ${vuln.root} && npm audit fix ${vuln.name}` : 'N/A';
      console.log(`    Fix: ${fixCommand}`);
    });

    console.log('\n' + '-'.repeat(60) + '\n');
  }
};

export default { scanNpm, printPretty };

