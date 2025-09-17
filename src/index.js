#!/usr/bin/env node
import path from 'path';
import fs from 'fs';
import { scanNpm, printPretty as printNpm } from './modules/npm-scan.js';
import { scan as scanPython, printPretty as printPython } from './modules/python-scan.js';

const args = process.argv.slice(2);
let targetDir = '.';
let outputFile = null;
let jsonOutput = false;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '-o' || arg === '--output') {
    outputFile = args[i + 1];
    i++;
  } else if (arg === '--json') {
    jsonOutput = true;
  } else if (arg === '-h' || arg === '--help') {
    console.log(`
LVS - Local Vulnerability Scanner

Usage:
  lvs [directory] [options]

Options:
  -h, --help       Show this help
  --json           Output results in JSON format
  -o, --output     Save results to file

Example:
  lvs ./my-project --json -o report.json
`);
    process.exit(0);
  } else {
    targetDir = arg;
  }
}

(async () => {
  const absDir = path.resolve(targetDir);
  const npmResults = await scanNpm(absDir);
  const pyResults = await scanPython(absDir);
  const allResults = [...npmResults, ...pyResults];

  if (jsonOutput) {
    const jsonData = JSON.stringify(allResults, null, 2);
    if (outputFile) fs.writeFileSync(outputFile, jsonData, 'utf8');
    console.log(jsonData);
  } else {
    let hasVulns = allResults.some(res => res.amount > 0);

    if (!hasVulns) {
      console.log(`✅ No vulnerabilities found in ${absDir}!`);
    } else {
      allResults.forEach(res => {
        if (res.scanner === 'npm') printNpm([res]);
        else if (res.scanner === 'python') printPython([res]);
      });
    }

    if (outputFile) {
      const output = allResults.map(res => `Root: ${res.root}\nVulnerabilities: ${res.amount}`).join('\n\n');
      fs.writeFileSync(outputFile, output, 'utf8');
    }
  }
})();

