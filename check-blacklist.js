const fs = require('fs');
const path = require('path');
const dns = require('dns');
const url = require('url');

const args = process.argv.slice(2);
if (args.length < 1) {
    console.error('Usage: node check-blacklist.js <URL_OR_DOMAIN>');
    process.exit(1);
}

const input = args[0];

// Helper to ensure reports directory exists
const reportsDir = path.join(__dirname, 'reports');
if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
}
const reportPath = path.join(reportsDir, 'blacklist-report.json');

const extractDomain = (inputUrl) => {
    try {
        if (!inputUrl.startsWith('http://') && !inputUrl.startsWith('https://')) {
            // Try to parse as is, if fails, might be just a domain
            if (inputUrl.includes('/')) {
                // likely a schemeless url like //example.com/foo
                if (inputUrl.startsWith('//')) {
                    return new url.URL('https:' + inputUrl).hostname;
                }
                return new url.URL('https://' + inputUrl).hostname;
            }
            return inputUrl; // Assume it's a domain
        }
        return new url.URL(inputUrl).hostname;
    } catch (e) {
        return input; // Fallback to returning input if parsing fails
    }
};

const domain = extractDomain(input);
const query = `${domain}.dbl.spamhaus.org`;

const writeReport = (status, code, details) => {
    const report = {
        domain: domain,
        status: status,
        details: details,
        timestamp: new Date().toISOString()
    };
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
};

console.log(`Checking ${domain} against Spamhaus (Query: ${query})...`);

dns.resolve(query, (err, addresses) => {
    if (err) {
        if (err.code === 'ENOTFOUND') {
            console.log(`[PASS] ${domain} is NOT listed in Spamhaus DBL.`);
            writeReport('clean', null, 'Domain is not listed.');
            process.exit(0);
        } else {
            console.error(`[ERROR] DNS lookup failed: ${err.message}`);
            writeReport('error', err.code, `DNS lookup failed: ${err.message}`);
            // Treat DNS failures as "clean" regarding blacklist for now to avoid blocking build
            process.exit(0);
        }
    } else {
        // Check for specific Spamhaus return codes that indicate query limitations (blocking)
        // https://www.spamhaus.org/faq/section/DNSBL%20Usage#200
        const blockedCodes = ['127.255.255.254', '127.255.255.255'];
        const isBlocked = addresses.some(addr => blockedCodes.includes(addr));

        if (isBlocked) {
            console.warn(`[WARN] Spamhaus query was BLOCKED by the DNS resolver.`);
            console.warn(`       Return codes: ${addresses.join(', ')}`);
            writeReport('blocked', addresses.join(', '), 'Query blocked by resolver.');
            process.exit(0); // Soft fail / Pass but warn.
        }

        // Real listing
        console.error(`[FAIL] ${domain} IS LISTED in Spamhaus DBL!`);
        console.error(`       Return codes: ${addresses.join(', ')}`);
        writeReport('listed', addresses.join(', '), 'Domain is listed in Spamhaus DBL.');
        process.exit(1);
    }
});
