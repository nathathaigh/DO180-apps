// security-scan.js — Claude AI security review + combined report
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const SCAN_DIR = path.join(__dirname, 'nodejs-app');
const EXTENSIONS = ['.js', '.ts', '.mjs', '.cjs'];

// ── Collect JS files ──────────────────────────────────────────────────────
function collectFiles(dir) {
  let results = [];
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results = results.concat(collectFiles(full));
    else if (EXTENSIONS.includes(path.extname(entry.name))) results.push(full);
  }
  return results;
}

// ── Collect npm audit report ──────────────────────────────────────────────
function getNpmAuditReport() {
  try {
    const raw = execSync('npm audit --json', { cwd: SCAN_DIR }).toString();
    return JSON.parse(raw);
  } catch (e) {
    // npm audit exits with code 1 when vulnerabilities found — output is still valid JSON
    try { return JSON.parse(e.stdout?.toString() || '{}'); } catch { return {}; }
  }
}

// ── Collect ZAP report ────────────────────────────────────────────────────
function getZapReport() {
  const zapPath = path.join(__dirname, 'report_json.json');
  if (!fs.existsSync(zapPath)) return null;
  try { return JSON.parse(fs.readFileSync(zapPath, 'utf8')); } catch { return null; }
}

// ── Claude combined analysis ──────────────────────────────────────────────
async function analyzeWithClaude({ sourceFiles, npmAudit, zapReport }) {
  // Build source code summary
  const sourceSummary = sourceFiles.map(f => {
    const rel = path.relative(__dirname, f);
    const code = fs.readFileSync(f, 'utf8');
    return `### ${rel}\n\`\`\`\n${code}\n\`\`\``;
  }).join('\n\n');

  // Build npm audit summary
  const auditSummary = npmAudit?.metadata
    ? `Vulnerabilities: ${JSON.stringify(npmAudit.metadata.vulnerabilities)}`
    : 'npm audit report not available';

  // Build ZAP summary
  const zapSummary = zapReport
    ? `ZAP found ${zapReport.site?.[0]?.alerts?.length || 0} alerts`
    : 'ZAP report not available';

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
      messages: [{
        role: 'user',
        content: `You are a senior security engineer. Analyze all security data below and produce a combined security report.

## Source Code
${sourceSummary}

## npm audit Report
${auditSummary}

## OWASP ZAP Report
${zapSummary}

Return ONLY a valid JSON object in this exact format:
{
  "overall_severity": "high" | "medium" | "low" | "none",
  "pass": true | false,
  "summary": "<2-3 sentence overall summary>",
  "findings": [
    {
      "source": "source_code" | "npm_audit" | "zap",
      "severity": "high" | "medium" | "low",
      "title": "<short title>",
      "detail": "<what the issue is>",
      "fix": "<how to fix it>"
    }
  ]
}

Set "pass" to false if overall_severity is "high" or "medium".`,
      }],
    }),
  });

  if (!response.ok) throw new Error(`API error ${response.status}: ${await response.text()}`);
  const data = await response.json();
  const raw = data.content.map(b => b.text || '').join('');
  return JSON.parse(raw.replace(/```json|```/g, '').trim());
}

// ── Print report ──────────────────────────────────────────────────────────
function printReport(result) {
  const icon = { high: '🔴', medium: '🟡', low: '🔵', none: '✅' };

  console.log('\n' + '═'.repeat(60));
  console.log('       COMBINED SECURITY REPORT');
  console.log('═'.repeat(60));
  console.log(`Overall Severity : ${icon[result.overall_severity]} ${result.overall_severity.toUpperCase()}`);
  console.log(`Status           : ${result.pass ? '✅ PASSED' : '❌ FAILED'}`);
  console.log(`\nSummary: ${result.summary}`);
  console.log('\n' + '─'.repeat(60));
  console.log('FINDINGS');
  console.log('─'.repeat(60));

  if (result.findings.length === 0) {
    console.log('  No issues found.');
  } else {
    result.findings.forEach((f, i) => {
      console.log(`\n  ${i + 1}. [${icon[f.severity]} ${f.severity.toUpperCase()}] [${f.source}] ${f.title}`);
      console.log(`     Issue : ${f.detail}`);
      console.log(`     Fix   : ${f.fix}`);
    });
  }

  console.log('\n' + '═'.repeat(60));
}

// ── Main ──────────────────────────────────────────────────────────────────
async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('❌  ANTHROPIC_API_KEY is not set.');
    process.exit(1);
  }

  console.log('\n📦  Collecting reports...');
  const sourceFiles = collectFiles(SCAN_DIR);
  console.log(`  ✅ Source files   : ${sourceFiles.length} file(s)`);

  const npmAudit = getNpmAuditReport();
  console.log(`  ✅ npm audit      : ${npmAudit?.metadata ? JSON.stringify(npmAudit.metadata.vulnerabilities) : 'not available'}`);

  const zapReport = getZapReport();
  console.log(`  ✅ ZAP report     : ${zapReport ? `${zapReport.site?.[0]?.alerts?.length || 0} alert(s)` : 'not available'}`);

  console.log('\n🤖  Sending to Claude for combined analysis...\n');

  try {
    const result = await analyzeWithClaude({ sourceFiles, npmAudit, zapReport });
    printReport(result);

    // Save JSON report
    const reportPath = path.join(__dirname, 'security-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(result, null, 2));
    console.log(`\n📄  Full report saved to: security-report.json`);

    process.exit(result.pass ? 0 : 1);
  } catch (err) {
    console.error(`❌  Claude analysis failed: ${err.message}`);
    process.exit(1);
  }
}

main();
