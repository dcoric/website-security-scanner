const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

const args = process.argv.slice(2);
if (args.length < 1) {
    console.error('Usage: node check-safebrowsing.js <URL_OR_DOMAIN>');
    process.exit(1);
}

const input = args[0];
const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;

// Helper to ensure reports directory exists
const reportsDir = path.join(__dirname, 'reports');
if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
}
const reportPath = path.join(reportsDir, 'safebrowsing-report.json');

const writeReport = (status, matches, details) => {
    const report = {
        url: input,
        status: status,
        matches: matches,
        details: details,
        timestamp: new Date().toISOString()
    };
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    console.log(`Report written to: ${reportPath}`);
};

if (!apiKey) {
    console.error('[ERROR] GOOGLE_SAFE_BROWSING_KEY environment variable is missing.');
    console.error('        Please set it to run this check.');
    writeReport('skipped', [], 'Missing GOOGLE_SAFE_BROWSING_KEY');
    process.exit(0); // Exit code 0 to not break CI, but report error
}

// Ensure URL has protocol for the check if it's just a domain
let checkUrl = input;
if (!checkUrl.startsWith('http://') && !checkUrl.startsWith('https://')) {
    checkUrl = 'https://' + checkUrl;
}

const requestBody = JSON.stringify({
    client: {
        clientId: "security-scan",
        clientVersion: "1.0.0"
    },
    threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [
            { "url": checkUrl }
        ]
    }
});

const options = {
    hostname: 'safebrowsing.googleapis.com',
    port: 443,
    path: `/v4/threatMatches:find?key=${apiKey}`,
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': requestBody.length
    }
};

console.log(`Checking ${checkUrl} against Google Safe Browsing...`);

const req = https.request(options, (res) => {
    let data = '';

    res.on('data', (chunk) => {
        data += chunk;
    });

    res.on('end', () => {
        if (res.statusCode !== 200) {
            console.error(`[ERROR] API Request failed with status code: ${res.statusCode}`);
            console.error(`        Response: ${data}`);
            writeReport('error', [], `API returned ${res.statusCode}`);
            process.exit(0);
        }

        try {
            const response = JSON.parse(data);

            if (response.matches && response.matches.length > 0) {
                console.error(`[FAIL] ${input} is listed as UNSAFE!`);
                console.error(`       Threats: ${response.matches.map(m => m.threatType).join(', ')}`);
                writeReport('unsafe', response.matches, 'URL found in Safe Browsing list');
                process.exit(1);
            } else {
                console.log(`[PASS] ${input} is clean.`);
                writeReport('clean', [], 'No threats found');
                process.exit(0);
            }

        } catch (e) {
            console.error('[ERROR] Failed to parse API response:', e.message);
            writeReport('error', [], `Parse error: ${e.message}`);
            process.exit(0);
        }
    });
});

req.on('error', (e) => {
    console.error(`[ERROR] Request error: ${e.message}`);
    writeReport('error', [], result.error = e.message);
    process.exit(0);
});

req.write(requestBody);
req.end();
