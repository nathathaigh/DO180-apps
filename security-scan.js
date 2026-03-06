// security-scan.js — Claude AI security review for CI pipeline
const fs = require('fs');
const path = require('path');

const FILES_TO_SCAN = ['app.js'];

async function scanWithClaude(filePath) {
  const code = fs.readFileSync(filePath, 'utf8');

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
Analyze the code below for security vulnerabilities.

Return ONLY a valid JSON object — no markdown, no explanation — in this exact format:
{
  "severity": "high" | "medium" | "low" | "none",
  "pass": true | false,
  "issues": [
    { "line": <number or null>, "issue": "<description>", "fix": "<recommended fix>" }
  ]
}

Set "pass" to false if severity is "high" or "medium".

Code from ${filePath}:
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
  return JSON.parse(clean);
}

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('❌  ANTHROPIC_API_KEY is not set.');
    process.exit(1);
  }

  let failed = false;

  for (const file of FILES_TO_SCAN) {
    if (!fs.existsSync(file)) {
      console.warn(`⚠️  Skipping ${file} — file not found.`);
      continue;
    }

    console.log(`\n🔍  Scanning ${file} with Claude...`);

    try {
      const result = await scanWithClaude(file);

      if (result.issues.length === 0) {
        console.log(`✅  No issues found in ${file}.`);
      } else {
        console.log(`\n📋  Results for ${file} [severity: ${result.severity.toUpperCase()}]`);
        result.issues.forEach((issue, i) => {
          const line = issue.line ? `line ${issue.line}` : 'general';
          console.log(`\n  ${i + 1}. [${line}] ${issue.issue}`);
          console.log(`     Fix: ${issue.fix}`);
        });
      }

      if (!result.pass) {
        console.log(`\n❌  ${file} failed security review.`);
        failed = true;
      } else {
        console.log(`\n✅  ${file} passed security review.`);
      }
    } catch (err) {
      console.error(`❌  Error scanning ${file}: ${err.message}`);
      failed = true;
    }
  }

  console.log(failed ? '\n🚨  Pipeline blocked — fix issues above.' : '\n🎉  All files passed.');
  process.exit(failed ? 1 : 0);
}

main();
