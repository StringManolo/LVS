#!/usr/bin/env node

import { scanNpm, printPretty } from './modules/npm-scan.js';
import path from 'path';
import fs from 'fs';

const args = process.argv.slice(2);

function showHelp() {
  console.log(`
Usage: lvs [options] [path]

Options:
  -h, --help           Show this help message
  -v, --version        Show version
  --json               Print results in JSON instead of pretty print
  -o, --output <file>  Save results to a file (works with JSON or pretty output)

Examples:
  lvs                       Show this help
  lvs /path/to/project      Scan a specific directory
  lvs --json -o results.json  Save results in JSON format
  lvs -o results.txt        Save pretty output to a text file
`);
}

async function main() {
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    const pkg = (await import('./package.json', { assert: { type: 'json' } })).default;
    console.log(pkg.version || '0.0.0');
    process.exit(0);
  }

  const asJson = args.includes('--json');

  // Detect output flag
  let outputFile = null;
  let cleanArgs = [...args];
  const outIndex = args.findIndex((a) => a === '-o' || a === '--output');
  if (outIndex !== -1 && args[outIndex + 1]) {
    outputFile = path.resolve(args[outIndex + 1]);
    cleanArgs.splice(outIndex, 2); // remove flag + file from args
  }

  // First non-flag argument is target path
  const targetPath =
    cleanArgs.find((a) => !a.startsWith('-')) || null;

  if (!targetPath) {
    showHelp();
    process.exit(0);
  }

  const absPath = path.resolve(targetPath);

  try {
    const results = await scanNpm(absPath);

    // Check if there are any vulnerabilities
    const hasVulns = results.some(r => r.amount && r.amount > 0);

    if (!hasVulns) {
      const message = `✅ No vulnerabilities found in ${absPath}!`;
      if (outputFile) {
        fs.writeFileSync(outputFile, message + '\n', 'utf8');
        console.log(`✅ Results saved to ${outputFile}`);
      } else {
        console.log(message);
      }
      process.exit(0);
    }

    if (asJson) {
      const jsonOutput = JSON.stringify(results, null, 2);
      if (outputFile) {
        fs.writeFileSync(outputFile, jsonOutput, 'utf8');
        console.log(`✅ Results saved to ${outputFile}`);
      } else {
        console.log(jsonOutput);
      }
    } else {
      if (outputFile) {
        const logs = [];
        const originalLog = console.log;
        console.log = (...args) => logs.push(args.join(' '));

        printPretty(results);

        console.log = originalLog;
        fs.writeFileSync(outputFile, logs.join('\n'), 'utf8');
        console.log(`✅ Pretty results saved to ${outputFile}`);
      } else {
        printPretty(results);
      }
    }
  } catch (err) {
    console.error('❌ Error running scan:', err);
    process.exit(1);
  }
}

main();

