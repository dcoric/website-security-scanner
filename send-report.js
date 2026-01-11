const fs = require('fs');
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

async function generateReportContent(retireSummary, clamavSummary, totalIssues) {
    if (!llmProvider || !llmApiKey) {
        console.log('LLM_PROVIDER or LLM_API_KEY not set. Using default template.');
        return null;
    }

    const prompt = `
    You are a cybersecurity expert reporter. I have run a security scan on the website: ${targetUrl}.
    
    Scan is run on ${new Date().toLocaleString()}

    Here are the raw results:
    
    [Retire.js (Client-Side Vulnerabilities)]
    ${retireSummary.replace(/<[^>]*>/g, '') /* Strip HTML for prompt */}
    
    [ClamAV (Malware Detection)]
    ${clamavSummary.replace(/<[^>]*>/g, '')}
    
    Total Issues Found: ${totalIssues}
    
    Task: Write a professional, concise email report in HTML format summarizing these findings.
    - If there are issues, highlight them and explain the potential risk.
    - If there are no issues, certify that the scan passed.
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
        if (fs.existsSync('retire-report.json')) {
            const retireData = JSON.parse(fs.readFileSync('retire-report.json', 'utf8'));
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
        if (fs.existsSync('clamav-report.txt')) {
            const txt = fs.readFileSync('clamav-report.txt', 'utf8');
            const match = txt.match(/Infected files: (\d+)/);
            if (match && parseInt(match[1]) > 0) {
                clamavIssues = parseInt(match[1]);
                clamavHtml = txt.split('\n').filter(l => l.includes('FOUND')).join('<br>');
            }
        }
    } catch (e) { }
    if (clamavIssues === 0) clamavHtml = 'No malware found.';

    // 2. Generate Content
    let htmlContent = await generateReportContent(retireHtml, clamavHtml, retireIssues + clamavIssues);

    if (!htmlContent) {
        // Fallback Template
        htmlContent = `
            <h2>Security Scan Report for ${targetUrl}</h2>
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

    const subject = `WebsiteSecurity Report: ${(retireIssues + clamavIssues) > 0 ? "Issues Found" : "Clean"}`;

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
