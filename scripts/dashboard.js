const fs = require('fs');
const path = require('path');

const reportPath = '/tmp/warp_status_report.txt';
const screenshotsDir = '/tmp/warp_status_screenshots';

if (!fs.existsSync(reportPath)) {
  console.error('Report not found:', reportPath);
  console.error('Run ./scripts/verify_everything.sh first');
  process.exit(1);
}

const report = fs.readFileSync(reportPath, 'utf8');

const screenshots = fs.existsSync(screenshotsDir)
  ? fs.readdirSync(screenshotsDir).filter(f => f.endsWith('.png'))
  : [];

const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Warp_Open Test Dashboard</title>
  <meta charset="utf-8">
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #1e1e2f;
      color: #d1d5db;
      padding: 20px;
      margin: 0;
    }
    h1 {
      color: #60a5fa;
      border-bottom: 2px solid #3b82f6;
      padding-bottom: 10px;
    }
    h2 {
      color: #34d399;
      margin-top: 2em;
    }
    pre {
      background: #2a2a3a;
      padding: 16px;
      border-radius: 8px;
      overflow-x: auto;
      border: 1px solid #444;
      font-size: 13px;
      line-height: 1.5;
    }
    .screenshots {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      margin-top: 16px;
    }
    .screenshot {
      border: 2px solid #444;
      border-radius: 8px;
      overflow: hidden;
      background: #2a2a3a;
    }
    .screenshot img {
      display: block;
      max-width: 500px;
      height: auto;
    }
    .screenshot-label {
      padding: 8px 12px;
      background: #1a1a1a;
      color: #9ca3af;
      font-size: 12px;
      font-family: monospace;
    }
  </style>
</head>
<body>
  <h1>🚀 Warp_Open Test Dashboard</h1>
  
  <h2>📋 Test Report</h2>
  <pre>${report.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
  
  <h2>📸 Screenshots</h2>
  ${screenshots.length > 0 
    ? `<div class="screenshots">
        ${screenshots.map(f => `
          <div class="screenshot">
            <img src="file://${path.join(screenshotsDir, f)}" alt="${f}" />
            <div class="screenshot-label">${f}</div>
          </div>
        `).join('')}
       </div>`
    : '<p>No screenshots found.</p>'
  }
  
  <h2>ℹ️ Info</h2>
  <ul>
    <li>Report: <code>${reportPath}</code></li>
    <li>Screenshots: <code>${screenshotsDir}</code></li>
    <li>Generated: ${new Date().toLocaleString()}</li>
  </ul>
</body>
</html>
`;

const outputPath = '/tmp/warp_status_dashboard.html';
fs.writeFileSync(outputPath, html);

console.log('✅ Dashboard generated:', outputPath);
console.log('   Open with: open', outputPath);
