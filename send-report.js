const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const { OpenAI } = require('openai');
const { GoogleGenerativeAI } = require('@google/generative-ai');

// Configuration
const smtpHost = process.env.SMTP_HOST;
const smtpPort = process.env.SMTP_PORT || 587;
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const emailFrom = process.env.EMAIL_FROM;
const emailTo = process.env.EMAIL_TO;
const targetUrl = process.env.TARGET_URL || 'Unknown Website';

// LLM Configuration
const llmProvider = (process.env.LLM_PROVIDER || '').toLowerCase(); // openai, deepseek, gemini, custom
const llmApiKey = process.env.LLM_API_KEY;
const llmModel = process.env.LLM_MODEL; // e.g. gpt-4o, gemini-pro, deepseek-chat
const llmBaseUrl = process.env.LLM_BASE_URL;
const reportsDir = path.join(__dirname, 'reports');

// CLI flags
const args = process.argv.slice(2);
const localMode = args.includes('--local') || args.includes('-l');

async function generateReportContent(retireSummary, clamavSummary, deadDomainSummary, blacklistSummary, totalIssues, scanMetrics) {
    if (!llmProvider || !llmApiKey) {
        console.log('LLM_PROVIDER or LLM_API_KEY not set. Using default template.');
        return null;
    }

    const prompt = `
    You are a cybersecurity expert reporter. I have run a security scan on the website: ${targetUrl}.
    
    Scan is run on ${new Date().toLocaleString()}

    Here are the raw results:

    [Spamhaus Domain Blocklist]
    ${blacklistSummary || 'Data not available.'}

    [Dead Domain Scan (Critical - Potential Subdomain Takeover)]
    ${deadDomainSummary || 'No dead domains found.'}
    
    [Retire.js (Client-Side Vulnerabilities)]
    ${retireSummary.replace(/<[^>]*>/g, '') /* Strip HTML for prompt */}
    
    [ClamAV (Malware Detection)]
    ${clamavSummary.replace(/<[^>]*>/g, '')}
    
    Total Issues Found: ${totalIssues}
    Pages Scanned: ${scanMetrics ? scanMetrics.scannedUrlCount : 'Unknown'}
    Scripts Downloaded: ${scanMetrics ? scanMetrics.downloadedScriptCount : 'Unknown'}
    
    Task: Write a professional, concise email report in HTML format summarizing these findings.
    - If there are issues, highlight them and explain the potential risk.
    - If there are no issues, certify that the scan passed.
    - Include metrics about the scan (number of pages, number of checked files).
    - Add information that all report files are stored on the server from where scan was run.
    - Use a professional tone.
    - Output ONLY the HTML body content (do not include <html> or <body> tags, just the inner content).
    - Use clear headings and lists.
    `;

    console.log(`Generating report using ${llmProvider}...`);

    try {
        if (llmProvider === 'gemini') {
            const genAI = new GoogleGenerativeAI(llmApiKey);
            const model = genAI.getGenerativeModel({ model: llmModel || 'gemini-pro' });
            const result = await model.generateContent(prompt);
            const response = await result.response;
            return response.text().replace(/```html/g, '').replace(/```/g, '');
        }
        else {
            // OpenAI compatible (OpenAI, DeepSeek, Custom)
            let baseURL = llmBaseUrl;
            let defaultModel = 'gpt-3.5-turbo';

            if (llmProvider === 'deepseek') {
                baseURL = baseURL || 'https://api.deepseek.com';
                defaultModel = 'deepseek-chat';
            } else if (llmProvider === 'custom') {
                if (!baseURL) throw new Error('LLM_BASE_URL is required for custom provider');
            }

            const openai = new OpenAI({
                apiKey: llmApiKey,
                baseURL: baseURL
            });

            const completion = await openai.chat.completions.create({
                messages: [{ role: "system", content: "You are a helpful security assistant." }, { role: "user", content: prompt }],
                model: llmModel || defaultModel,
            });

            return completion.choices[0].message.content.replace(/```html/g, '').replace(/```/g, '');
        }
    } catch (error) {
        console.error('LLM Generation Failed:', error.message);
        return null; // Fallback to default
    }
}

async function generateReport() {
    // 1. Gather Data
    let retireIssues = 0;
    let retireHtml = '';
    // ... [Same parsing logic as before, abbreviated for brevity in this step update] ...
    // Re-implementing parsing logic efficiently:
    try {
        const retirePath = path.join(reportsDir, 'retire-report.json');
        if (fs.existsSync(retirePath)) {
            const retireData = JSON.parse(fs.readFileSync(retirePath, 'utf8'));
            if (Array.isArray(retireData)) {
                retireData.forEach(fileOpt => {
                    if (fileOpt.results && fileOpt.results.length > 0) {
                        retireIssues += fileOpt.results.length;
                        retireHtml += `<p><strong>${fileOpt.file}</strong>: ${fileOpt.results.length} vulnerabilities.</p>`;
                        fileOpt.results.forEach(v => retireHtml += `<li>${v.component} ${v.version}</li>`);
                    }
                });
            }
        }
    } catch (e) { } // Ignore

    if (retireIssues === 0) retireHtml = 'No vulnerabilities found.';

    let clamavIssues = 0;
    let clamavHtml = '';
    try {
        const clamavPath = path.join(reportsDir, 'clamav-report.txt');
        if (fs.existsSync(clamavPath)) {
            const rawTxt = fs.readFileSync(clamavPath, 'utf8');
            const summaryMarker = '----------- SCAN SUMMARY -----------';
            const markerIndex = rawTxt.indexOf(summaryMarker);
            const txt = markerIndex >= 0 ? rawTxt.slice(markerIndex) : rawTxt;
            const match = txt.match(/Infected files: (\d+)/);
            if (match && parseInt(match[1]) > 0) {
                clamavIssues = parseInt(match[1]);
                clamavHtml = txt.split('\n').filter(l => l.includes('FOUND')).join('<br>');
            }
        }
    } catch (e) { }
    if (clamavIssues === 0) clamavHtml = 'No malware found.';

    let deadDomainIssues = 0;
    let deadDomainHtml = '';
    let deadDomainSummary = '';
    try {
        const deadDomainsPath = path.join(reportsDir, 'dead-domains.json');
        if (fs.existsSync(deadDomainsPath)) {
            const data = JSON.parse(fs.readFileSync(deadDomainsPath, 'utf8'));
            if (data.deadDomains && data.deadDomains.length > 0) {
                deadDomainIssues = data.deadDomains.length;
                deadDomainHtml = '<ul>' + data.deadDomains.map(d => {
                    let sourcesHtml = '';
                    if (d.sources && d.sources.length > 0) {
                        sourcesHtml = '<ul style="font-size: 0.9em; color: #555;">' + d.sources.map(s => `<li>${s}</li>`).join('') + '</ul>';
                    }
                    return `<li><strong>${d.domain}</strong>: ${d.error}${sourcesHtml}</li>`;
                }).join('') + '</ul>';

                deadDomainSummary = data.deadDomains.map(d => {
                    const sources = (d.sources || []).map(s => `    - ${s}`).join('\n');
                    return `- ${d.domain} (${d.error})\n${sources}`;
                }).join('\n');
            }
        }
    } catch (e) { }
    if (deadDomainIssues === 0) deadDomainHtml = 'No dead domains found.';

    // 1.5 Blacklist Scan
    let blacklistIssues = 0;
    let blacklistHtml = '';
    let blacklistSummary = '';
    try {
        const blacklistPath = path.join(reportsDir, 'blacklist-report.json');
        if (fs.existsSync(blacklistPath)) {
            const data = JSON.parse(fs.readFileSync(blacklistPath, 'utf8'));
            if (data.status === 'listed') {
                blacklistIssues = 1;
                blacklistHtml = `<p style="color: red;"><strong>[FAIL] ${data.domain}</strong> is listed in Spamhaus DBL!</p>`;
                blacklistSummary = `[FAIL] ${data.domain} is LISTED in Spamhaus DBL.`;
            } else if (data.status === 'blocked') {
                blacklistHtml = `<p style="color: orange;"><strong>[WARN]</strong> Spamhaus query blocked. Use a private resolver.</p>`;
                blacklistSummary = `[WARN] Spamhaus query blocked.`;
            } else if (data.status === 'clean') {
                blacklistHtml = `<p style="color: green;"><strong>[PASS]</strong> ${data.domain} is clean.</p>`;
                blacklistSummary = `[PASS] ${data.domain} is clean.`;
            }
        }
    } catch (e) { }

    // 2. Generate Content
    let scanMetrics = null;
    try {
        const metadataPath = path.join(reportsDir, 'scan-metadata.json');
        if (fs.existsSync(metadataPath)) {
            scanMetrics = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
        }
    } catch (e) {
        console.error('Failed to read scan metadata:', e.message);
    }

    let htmlContent = await generateReportContent(retireHtml, clamavHtml, deadDomainSummary, blacklistSummary, retireIssues + clamavIssues + deadDomainIssues + blacklistIssues, scanMetrics);

    if (!htmlContent) {
        // Fallback Template
        htmlContent = `
            <h2>Security Scan Report for ${targetUrl}</h2>
            <p><strong>Pages Scanned:</strong> ${scanMetrics ? scanMetrics.scannedUrlCount : 'Unknown'}</p>
            <p><strong>Scripts Downloaded:</strong> ${scanMetrics ? scanMetrics.downloadedScriptCount : 'Unknown'}</p>
            
            <h3>Spamhaus Blacklist</h3>
            ${blacklistHtml}

            <h3>Dead Domains (Critical)</h3>
            ${deadDomainHtml}

            <h3>Retire.js</h3>
            ${retireHtml}
            
            <h3>ClamAV</h3>
            ${clamavHtml}
        `;
    }

    // 3. Output report
    // 3. Output report
    const totalIssues = retireIssues + clamavIssues + deadDomainIssues + blacklistIssues;
    const fullHtml = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Security Scan Report - ${targetUrl}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h2, h3 { color: #333; }
        ul { padding-left: 20px; }
        li { margin: 5px 0; }
    </style>
</head>
<body>
${htmlContent}
</body>
</html>`;

    // Always save HTML report locally
    const outputPath = path.join(reportsDir, 'report.html');
    fs.writeFileSync(outputPath, fullHtml);
    console.log(`Report saved to ${outputPath}`);

    // Skip email if --local flag or missing SMTP config
    if (localMode) {
        return;
    }

    if (!smtpHost || !emailTo) {
        console.log('SMTP_HOST or EMAIL_TO not set. Skipping email.');
        return;
    }

    const transporter = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort == 465,
        auth: (smtpUser && smtpPass) ? { user: smtpUser, pass: smtpPass } : undefined,
        ignoreTLS: true
    });

    const subject = `WebsiteSecurity Report: ${totalIssues > 0 ? "Issues Found" : "Clean"}`;

    try {
        await transporter.sendMail({
            from: emailFrom,
            to: emailTo,
            subject: subject,
            html: htmlContent,
        });
        console.log('Email sent successfully to ' + emailTo);
    } catch (err) {
        console.error('Error sending email:', err);
    }
}

generateReport();
