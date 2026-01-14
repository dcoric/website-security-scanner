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

async function generateReportContent(retireSummary, clamavSummary, deadDomainSummary, totalIssues, scanMetrics) {
    if (!llmProvider || !llmApiKey) {
        console.log('LLM_PROVIDER or LLM_API_KEY not set. Using default template.');
        return null;
    }

    const prompt = `
    You are a cybersecurity expert reporter. I have run a security scan on the website: ${targetUrl}.
    
    Scan is run on ${new Date().toLocaleString()}

    Here are the raw results:

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

async function sendEmail() {
    if (!smtpHost || !emailTo) {
        console.log('SMTP_HOST or EMAIL_TO not set. Skipping email report.');
        return;
    }

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

    let htmlContent = await generateReportContent(retireHtml, clamavHtml, deadDomainSummary, retireIssues + clamavIssues + deadDomainIssues, scanMetrics);

    if (!htmlContent) {
        // Fallback Template
        htmlContent = `
            <h2>Security Scan Report for ${targetUrl}</h2>
            <p><strong>Pages Scanned:</strong> ${scanMetrics ? scanMetrics.scannedUrlCount : 'Unknown'}</p>
            <p><strong>Scripts Downloaded:</strong> ${scanMetrics ? scanMetrics.downloadedScriptCount : 'Unknown'}</p>
            
            <h3>Dead Domains (Critical)</h3>
            ${deadDomainHtml}

            <h3>Retire.js</h3>
            ${retireHtml}
            
            <h3>ClamAV</h3>
            ${clamavHtml}
        `;
    }

    // 3. Send Email
    const transporter = nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort == 465,
        auth: (smtpUser && smtpPass) ? { user: smtpUser, pass: smtpPass } : undefined,
        ignoreTLS: true
    });

    const subject = `WebsiteSecurity Report: ${(retireIssues + clamavIssues + deadDomainIssues) > 0 ? "Issues Found" : "Clean"}`;

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

sendEmail();
