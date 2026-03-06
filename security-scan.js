// security-scan.js — Claude AI security review for CI pipeline
const fs = require('fs');
const path = require('path');

// ── Target folder ────────────────────────────────────────────────────────────
const SCAN_DIR = path.join(__dirname, 'nodejs-helloworld');
const EXTENSIONS = ['.js', '.ts', '.mjs', '.cjs'];

// Recursively collect all JS files under the target directory
function collectFiles(dir) {
  let results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue; // skip deps
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results = results.concat(collectFiles(full));
    } else if (EXTENSIONS.includes(path.extname(entry.name))) {
      results.push(full);
    }
  }
  return results;
}

// ── Claude scan ──────────────────────────────────────────────────────────────
async function scanWithClaude(filePath) {
  const code = fs.readFileSync(filePath, 'utf8');
  const relative = path.relative(__dirname, filePath);

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [
        {
          role: 'user',
          content: `You are a senior security engineer reviewing Node.js code.
Analyze the code below for security vulnerabilities (e.g. injection, missing headers, exposed secrets, insecure dependencies usage, unhandled errors).

Return ONLY a valid JSON object — no markdown, no explanation — in this exact format:
{
  "severity": "high" | "medium" | "low" | "none",
  "pass": true | false,
  "issues": [
    { "line": <number or null>, "issue": "<description>", "fix": "<recommended fix>" }
  ]
}

Set "pass" to false if severity is "high" or "medium".

File: ${relative}
\`\`\`
${code}
\`\`\``,
        },
      ],
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Anthropic API error ${response.status}: ${err}`);
  }

  const data = await response.json();
  const raw = data.content.map((b) => b.text || '').join('');
  const clean = raw.replace(/```json|```/g, '').trim();
  return { file: relative, ...JSON.parse(clean) };
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('❌  ANTHROPIC_API_KEY is not set.');
    process.exit(1);
  }

  const files = collectFiles(SCAN_DIR);

  if (files.length === 0) {
    console.warn(`⚠️  No JS files found in ${SCAN_DIR}`);
    process.exit(0);
  }

  console.log(`\n🔍  Scanning ${files.length} file(s) in nodejs-helloworld/...\n`);

  let failed = false;
  const summary = [];

  for (const file of files) {
    const relative = path.relative(__dirname, file);
    process.stdout.write(`  scanning ${relative} ... `);

    try {
      const result = await scanWithClaude(file);
      summary.push(result);

      if (result.issues.length === 0) {
        console.log('✅  clean');
      } else {
        console.log(`⚠️  ${result.severity.toUpperCase()} (${result.issues.length} issue(s))`);
        result.issues.forEach((issue, i) => {
          const line = issue.line ? `line ${issue.line}` : 'general';
          console.log(`      ${i + 1}. [${line}] ${issue.issue}`);
          console.log(`         Fix: ${issue.fix}`);
        });
      }

      if (!result.pass) failed = true;
    } catch (err) {
      console.log(`❌  error`);
      console.error(`     ${err.message}`);
      failed = true;
    }
  }

  // ── Summary table ───────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(60));
  console.log('SCAN SUMMARY');
  console.log('─'.repeat(60));
  summary.forEach((r) => {
    const icon = r.pass ? '✅' : '❌';
    console.log(`${icon}  [${r.severity.padEnd(6)}]  ${r.file}`);
  });
  console.log('─'.repeat(60));

  if (failed) {
    console.log('\n🚨  Pipeline blocked — fix the issues above before merging.');
    process.exit(1);
  } else {
    console.log('\n🎉  All files passed security review.');
    process.exit(0);
  }
}

main();
