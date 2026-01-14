const fs = require('fs');
const path = require('path');
const dns = require('dns');
const url = require('url');

const foundUrlsFile = path.join(__dirname, 'found_urls.json');
const foundUrlsLegacyFile = path.join(__dirname, 'found_urls.txt');
const jsAssetsDir = path.join(__dirname, 'js_assets');
const downloadedScriptsFile = path.join(__dirname, 'downloaded_scripts.json');

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
        return null; // Invalid URL
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

// Data Structure: Domain -> Set<SourceString>
const domainSources = new Map();

const addFinding = (foundUrl, source) => {
    const domain = extractDomain(foundUrl);
    if (!domain) return;

    if (!domainSources.has(domain)) {
        domainSources.set(domain, new Set());
    }
    const sources = domainSources.get(domain);
    // Avoid duplicate sources for same domain to keep report clean
    sources.add(source);
};

const run = async () => {
    console.log('--- Dead Domain Scanner ---');

    // 1. Read URLs from Page Scan (found_urls.json)
    if (fs.existsSync(foundUrlsFile)) {
        console.log('Reading URLs from crawl (JSON)...');
        try {
            const data = JSON.parse(fs.readFileSync(foundUrlsFile, 'utf-8'));
            // Expected format: [{ page: "...", urls: ["..."] }]
            data.forEach(item => {
                const pageUrl = item.page;
                if (Array.isArray(item.urls)) {
                    item.urls.forEach(u => {
                        addFinding(u, `Found on Page: ${pageUrl}`);
                    });
                }
            });
        } catch (e) {
            console.error('Error parsing found_urls.json:', e.message);
        }
    } else if (fs.existsSync(foundUrlsLegacyFile)) {
        // Fallback to legacy TXT
        console.log('Reading URLs from crawl (Legacy TXT)...');
        const lines = fs.readFileSync(foundUrlsLegacyFile, 'utf-8').split('\n');
        lines.forEach(line => {
            const trimmed = line.trim();
            if (trimmed) addFinding(trimmed, 'Found during Crawl (Source Unknown)');
        });
    }

    // 2. Load Script Metadata
    let scriptMap = new Map(); // filename -> { originalUrl, foundOnPage }
    if (fs.existsSync(downloadedScriptsFile)) {
        try {
            const scripts = JSON.parse(fs.readFileSync(downloadedScriptsFile, 'utf-8'));
            scripts.forEach(s => {
                scriptMap.set(s.filename, s);
            });
        } catch (e) {
            console.error('Error parsing downloaded_scripts.json:', e);
        }
    }

    // 3. Scan Downloaded JS assets
    if (fs.existsSync(jsAssetsDir)) {
        console.log('Scanning JS assets for URLs...');
        const files = getAllFiles(jsAssetsDir);
        for (const file of files) {
            if (file.endsWith('.js') || file.endsWith('.json') || file.endsWith('.map')) {
                try {
                    const content = fs.readFileSync(file, 'utf-8');
                    const matches = content.match(urlRegex) || [];
                    const filename = path.basename(file);

                    const scriptInfo = scriptMap.get(filename);
                    let sourceDescription;

                    if (scriptInfo) {
                        sourceDescription = `Found in Script: ${scriptInfo.originalUrl} (loaded by ${scriptInfo.foundOnPage})`;
                    } else {
                        sourceDescription = `Found in Script File: ${filename} (source unknown)`;
                    }

                    matches.forEach(m => addFinding(m, sourceDescription));
                } catch (err) {
                    console.error(`Error reading ${file}:`, err.message);
                }
            }
        }
    }

    // 4. Checking Domains
    const allDomains = Array.from(domainSources.keys());

    // Filter out common false positives or localhosts
    const domainsToCheck = allDomains.filter(d =>
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
                    if (err.code === 'ENOTFOUND') {
                        deadDomains.push({
                            domain: domain,
                            error: err.code,
                            sources: Array.from(domainSources.get(domain))
                        });
                    }
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

    const reportsDir = path.join(__dirname, 'reports');
    if (!fs.existsSync(reportsDir)) {
        fs.mkdirSync(reportsDir, { recursive: true });
    }
    fs.writeFileSync(path.join(reportsDir, 'dead-domains.json'), JSON.stringify(findings, null, 2));

    if (deadDomains.length > 0) {
        console.error('\n[CRITICAL] Found potentially dead domains/DNS entries:');
        deadDomains.forEach(d => {
            console.error(`\nDomain: ${d.domain} (${d.error})`);
            console.error(`Sources:`);
            d.sources.forEach(s => console.error(` - ${s}`));
        });
        console.error('\nFAILURE: Dead domains detected. Fix these to prevent takeover risks.');
        process.exit(1);
    } else {
        console.log('\nSUCCESS: No dead domains found.');
        process.exit(0);
    }
};

run();
