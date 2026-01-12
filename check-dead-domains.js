const fs = require('fs');
const path = require('path');
const dns = require('dns');
const url = require('url');

const foundUrlsFile = path.join(__dirname, 'found_urls.txt');
const jsAssetsDir = path.join(__dirname, 'js_assets');

// Helper to extract domains
const extractDomain = (urlString) => {
    try {
        // Handle protocol-less URLs (e.g. "//example.com")
        if (urlString.startsWith('//')) {
            urlString = 'https:' + urlString;
        }
        const parsed = new url.URL(urlString);
        return parsed.hostname;
    } catch (e) {
        return null;
    }
};

const getAllFiles = (dirPath, arrayOfFiles) => {
    const files = fs.readdirSync(dirPath);

    arrayOfFiles = arrayOfFiles || [];

    files.forEach((file) => {
        if (fs.statSync(dirPath + "/" + file).isDirectory()) {
            arrayOfFiles = getAllFiles(dirPath + "/" + file, arrayOfFiles);
        } else {
            arrayOfFiles.push(path.join(dirPath, "/", file));
        }
    });

    return arrayOfFiles;
};

// Regex to find URLs in text content
const urlRegex = /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:[\/?#][^\s"']*)?/g;

const run = async () => {
    const allUrls = new Set();
    const allDomains = new Set();

    console.log('--- Dead Domain Scanner ---');

    // 1. Read URLs found during crawl
    if (fs.existsSync(foundUrlsFile)) {
        console.log('Reading URLs from crawl...');
        const lines = fs.readFileSync(foundUrlsFile, 'utf-8').split('\n');
        lines.forEach(line => {
            const trimmed = line.trim();
            if (trimmed) allUrls.add(trimmed);
        });
    }

    // 2. Scan downloaded JS assets for more URLs
    if (fs.existsSync(jsAssetsDir)) {
        console.log('Scanning JS assets for URLs...');
        const files = getAllFiles(jsAssetsDir);
        for (const file of files) {
            if (file.endsWith('.js') || file.endsWith('.json') || file.endsWith('.map')) {
                try {
                    const content = fs.readFileSync(file, 'utf-8');
                    const matches = content.match(urlRegex) || [];
                    matches.forEach(m => allUrls.add(m));
                } catch (err) {
                    console.error(`Error reading ${file}:`, err.message);
                }
            }
        }
    }

    // 3. Extract Domains
    console.log(`Found ${allUrls.size} unique URLs.`);
    for (const u of allUrls) {
        const domain = extractDomain(u);
        if (domain) {
            allDomains.add(domain);
        }
    }

    // Filter out common false positives or localhosts if needed
    const domainsToCheck = Array.from(allDomains).filter(d =>
        !d.includes('localhost') &&
        !d.includes('127.0.0.1') &&
        d.includes('.') // Must have a TLD
    );

    console.log(`Checking DNS for ${domainsToCheck.length} unique domains...`);

    const deadDomains = [];
    const checkPromises = domainsToCheck.map(domain => {
        return new Promise((resolve) => {
            dns.resolve(domain, (err) => {
                if (err) {
                    // Start simple: if resolve fails, it might be dead using 'A' record default
                    // We can refine this to check validation against specific error codes.
                    // ENOTFOUND is the main one for "domain does not exist".
                    if (err.code === 'ENOTFOUND') {
                        deadDomains.push({ domain, error: err.code });
                    }
                    // Other errors like timeouts might be temporary, but ENOTFOUND is strong signal.
                }
                resolve();
            });
        });
    });

    await Promise.all(checkPromises);

    const findings = {
        deadDomains: deadDomains,
        totalChecked: domainsToCheck.length,
        timestamp: new Date().toISOString()
    };

    fs.writeFileSync(path.join(__dirname, 'dead-domains.json'), JSON.stringify(findings, null, 2));

    if (deadDomains.length > 0) {
        console.error('\n[CRITICAL] Found potentially dead domains/DNS entries:');
        deadDomains.forEach(d => {
            console.error(` - ${d.domain} (${d.error})`);
        });
        console.error('\nFAILURE: Dead domains detected. Fix these to prevent takeover risks.');
        process.exit(1);
    } else {
        console.log('\nSUCCESS: No dead domains found.');
        process.exit(0);
    }
};

run();
