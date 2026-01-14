const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const https = require('https');
const http = require('http');
const xml2js = require('xml2js');

const targetUrl = process.argv[2];

if (!targetUrl) {
    console.error('Please provide a URL to scan.');
    process.exit(1);
}

const outputDir = path.join(__dirname, 'js_assets');
if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir);
}

const seenScripts = new Set();
const seenPages = new Set();
const maxPagesToVisit = 1500; // Limit to avoid endless crawling

const scriptSkipDomains = (process.env.SKIP_SCRIPT_DOMAINS || [
    'googleads.g.doubleclick.net',
    'g.doubleclick.net',
    'doubleclick.net',
    'googlesyndication.com',
    'googletagmanager.com',
    'google-analytics.com',
    'analytics.google.com',
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'connect.facebook.net',
    'platform.twitter.com',
    'twitter.com',
    'x.com',
    'platform.x.com',
    'youtube.com',
    's.ytimg.com',
    'ajax.googleapis.com',
    'cdnjs.cloudflare.com',
    'unpkg.com',
    'code.jquery.com',
    'cdn.jsdelivr.net',
    'www.google.com',
    'www.gstatic.com'
].join(','))
    .split(',')
    .map(d => d.trim())
    .filter(d => d.length > 0);

// Function to download a file
const downloadFile = (url, dest) => {
    const file = fs.createWriteStream(dest);
    const protocol = url.startsWith('https') ? https : http;

    return new Promise((resolve, reject) => {
        protocol.get(url, (response) => {
            if (response.statusCode !== 200) {
                reject(new Error(`Failed to download ${url}: ${response.statusCode}`));
                return;
            }
            response.pipe(file);
            file.on('finish', () => {
                file.close(() => resolve(dest));
            });
        }).on('error', (err) => {
            fs.unlink(dest, () => { });
            reject(err);
        });
    });
};

const isScriptDomainSkipped = (scriptUrl) => {
    if (scriptSkipDomains.length === 0) return false;
    try {
        const hostname = new URL(scriptUrl).hostname;
        return scriptSkipDomains.some(domain => hostname === domain || hostname.endsWith(`.${domain}`));
    } catch (e) {
        return false;
    }
};

async function parseSitemap(page, sitemapUrl) {
    console.log(`Fetching sitemap: ${sitemapUrl}`);
    try {
        await page.goto(sitemapUrl, { waitUntil: 'networkidle0' });
        // Get XML content directly from page content since browser handles it
        // Or specific evaluation if it renders as text.
        // Usually, headless chrome renders XML as text/html-like tree or raw text.
        // Better strategy: Use page.content() and try to parse it, OR use page.evaluate to fetch it.

        // Strategy: Use fetch inside the page context to get raw XML
        const xmlContent = await page.evaluate(async (url) => {
            const res = await fetch(url);
            return res.text();
        }, sitemapUrl);

        const parser = new xml2js.Parser();
        const result = await parser.parseStringPromise(xmlContent);

        let urls = [];

        // Handle Sitemap Index
        if (result.sitemapindex && result.sitemapindex.sitemap) {
            for (const sitemap of result.sitemapindex.sitemap) {
                const loc = sitemap.loc[0];
                urls = urls.concat(await parseSitemap(page, loc));
            }
        }
        // Handle Url Set
        else if (result.urlset && result.urlset.url) {
            urls = result.urlset.url.map(u => u.loc[0]);
        }

        return urls;

    } catch (e) {
        console.error(`Error parsing sitemap ${sitemapUrl}:`, e.message);
        return [];
    }
}

(async () => {
    console.log(`Launching browser...`);
    const browser = await puppeteer.launch({
        headless: "new",
        args: ['--no-sandbox']
    });
    const page = await browser.newPage();

    // User Agent to look like a real browser
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

    // 1. Get pages from Sitemap
    let pagesToVisit = [targetUrl]; // Start with homepage
    const sitemapUrl = targetUrl.endsWith('/') ? `${targetUrl}sitemap.xml` : `${targetUrl}/sitemap.xml`;

    console.log(`Attempting to find sitemap at ${sitemapUrl}...`);
    const sitemapPages = await parseSitemap(page, sitemapUrl);

    if (sitemapPages.length > 0) {
        console.log(`Found ${sitemapPages.length} pages in sitemap.`);
        pagesToVisit = [...new Set([...pagesToVisit, ...sitemapPages])];
    } else {
        console.log("No pages found in sitemap or sitemap failed. Scanning homepage only.");
    }

    // Limit pages
    if (pagesToVisit.length > maxPagesToVisit) {
        console.log(`Limiting scan to first ${maxPagesToVisit} pages.`);
        pagesToVisit = pagesToVisit.slice(0, maxPagesToVisit);
    }

    // Filter out skipped prefixes
    const skipPrefixes = (process.env.SKIP_URL_PREFIXES || '')
        .split(',')
        .map(p => p.trim())
        .filter(p => p.length > 0);

    const includePrefixes = (process.env.INCLUDE_URL_PREFIXES || '')
        .split(',')
        .map(p => p.trim())
        .filter(p => p.length > 0);

    if (skipPrefixes.length > 0) {
        console.log(`Skipping URLs starting with: ${skipPrefixes.join(', ')}`);
        if (includePrefixes.length > 0) {
            console.log(`But including URLs starting with: ${includePrefixes.join(', ')}`);
        }

        const originalCount = pagesToVisit.length;
        pagesToVisit = pagesToVisit.filter(url => {
            const urlPath = new URL(url).pathname;
            const matchesSkip = skipPrefixes.some(prefix => urlPath.startsWith(prefix));
            const matchesInclude = includePrefixes.some(prefix => urlPath.startsWith(prefix));

            // Skip if it matches a skip prefix AND does NOT match an include prefix
            const shouldSkip = matchesSkip && !matchesInclude;

            if (shouldSkip) {
                console.log(`Skipping ${url} (matches prefix)`);
            }
            return !shouldSkip;
        });
        console.log(`Filtered out ${originalCount - pagesToVisit.length} pages based on skip/include prefixes.`);
    }

    // 2. Visit Pages and Collect Scripts
    const foundUrlsFile = path.join(__dirname, 'found_urls.json');
    const downloadedScriptsFile = path.join(__dirname, 'downloaded_scripts.json');

    // Store findings in memory
    const allFoundUrls = []; // { page: string, urls: string[] }
    const downloadedScriptsData = []; // { filename: string, originalUrl: string, foundOnPage: string }

    let downloadedScriptsCount = 0;

    for (const pageUrl of pagesToVisit) {
        if (seenPages.has(pageUrl)) continue;
        seenPages.add(pageUrl);

        console.log(`Visiting ${pageUrl}...`);
        try {
            await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });

            // Extract generic URLs from page content
            const extractedUrls = await page.evaluate(() => {
                const urls = new Set();

                // 1. HREF attributes
                document.querySelectorAll('*[href]').forEach(el => urls.add(el.href));

                // 2. SRC attributes
                document.querySelectorAll('*[src]').forEach(el => urls.add(el.src));

                // 3. ACTION attributes (forms)
                document.querySelectorAll('form[action]').forEach(el => urls.add(el.action));

                // 4. Regex scan of full HTML for anything looking like a URL
                // This is aggressive but necessary to catch URLs in JS strings, data attributes, etc.
                const html = document.documentElement.outerHTML;
                const urlRegex = /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:[\/?#][^\s"']*)?/g;
                const matches = html.match(urlRegex) || [];
                matches.forEach(m => urls.add(m));

                return Array.from(urls);
            });

            allFoundUrls.push({
                page: pageUrl,
                urls: extractedUrls
            });

            const scripts = await page.evaluate(() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(src => src && !src.startsWith('chrome-extension://'));
            });

            for (const scriptUrl of scripts) {
                if (!seenScripts.has(scriptUrl)) {
                    seenScripts.add(scriptUrl);

                    try {
                        if (isScriptDomainSkipped(scriptUrl)) {
                            console.log(`--> Skipping ${scriptUrl} (whitelisted domain)`);
                            continue;
                        }
                        const fileName = path.basename(new URL(scriptUrl).pathname) || 'script.js';
                        const uniqueName = `${Date.now()}-${Math.floor(Math.random() * 1000)}-${fileName}`;
                        const destPath = path.join(outputDir, uniqueName);

                        console.log(`--> Downloading ${scriptUrl}`);
                        await downloadFile(scriptUrl, destPath);
                        downloadedScriptsCount += 1;

                        downloadedScriptsData.push({
                            filename: uniqueName,
                            originalUrl: scriptUrl,
                            foundOnPage: pageUrl
                        });
                    } catch (err) {
                        console.error(`Failed to handle script url ${scriptUrl}:`, err.message);
                    }
                }
            }

        } catch (err) {
            console.error(`Error visiting ${pageUrl}:`, err.message);
        }
    }

    console.log('Download complete.');
    console.log(`Scanned ${seenPages.size} pages.`);
    console.log(`Downloaded ${downloadedScriptsCount} unique scripts.`);

    // Write data files
    fs.writeFileSync(foundUrlsFile, JSON.stringify(allFoundUrls, null, 2));
    fs.writeFileSync(downloadedScriptsFile, JSON.stringify(downloadedScriptsData, null, 2));

    // Save metrics for report
    const metadata = {
        scannedUrlCount: seenPages.size,
        downloadedScriptCount: downloadedScriptsCount
    };
    const reportsDir = path.join(__dirname, 'reports');
    if (!fs.existsSync(reportsDir)) {
        fs.mkdirSync(reportsDir, { recursive: true });
    }
    fs.writeFileSync(path.join(reportsDir, 'scan-metadata.json'), JSON.stringify(metadata, null, 2));

    await browser.close();
})();
