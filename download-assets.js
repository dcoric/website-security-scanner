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
const maxPagesToVisit = 100; // Limit to avoid endless crawling

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

    if (skipPrefixes.length > 0) {
        console.log(`Skipping URLs starting with: ${skipPrefixes.join(', ')}`);
        const originalCount = pagesToVisit.length;
        pagesToVisit = pagesToVisit.filter(url => {
            const urlPath = new URL(url).pathname;
            const shouldSkip = skipPrefixes.some(prefix => urlPath.startsWith(prefix));
            if (shouldSkip) {
                console.log(`Skipping ${url} (matches prefix)`);
            }
            return !shouldSkip;
        });
        console.log(`Filtered out ${originalCount - pagesToVisit.length} pages based on skip prefixes.`);
    }

    // 2. Visit Pages and Collect Scripts
    for (const pageUrl of pagesToVisit) {
        if (seenPages.has(pageUrl)) continue;
        seenPages.add(pageUrl);

        console.log(`Visiting ${pageUrl}...`);
        try {
            await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });

            const scripts = await page.evaluate(() => {
                return Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(src => src && !src.startsWith('chrome-extension://'));
            });

            for (const scriptUrl of scripts) {
                if (!seenScripts.has(scriptUrl)) {
                    seenScripts.add(scriptUrl);

                    try {
                        const fileName = path.basename(new URL(scriptUrl).pathname) || 'script.js';
                        const uniqueName = `${Date.now()}-${Math.floor(Math.random() * 1000)}-${fileName}`;
                        const destPath = path.join(outputDir, uniqueName);

                        console.log(`--> Downloading ${scriptUrl}`);
                        await downloadFile(scriptUrl, destPath);
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
    console.log(`Downloaded ${seenScripts.size} unique scripts.`);

    await browser.close();
})();
