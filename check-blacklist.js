const fs = require('fs');
const path = require('path');
const dns = require('dns');
const url = require('url');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);
const resolve = promisify(dns.resolve);

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
            if (inputUrl.includes('/')) {
                if (inputUrl.startsWith('//')) {
                    return new url.URL('https:' + inputUrl).hostname;
                }
                return new url.URL('https://' + inputUrl).hostname;
            }
            return inputUrl;
        }
        return new url.URL(inputUrl).hostname;
    } catch (e) {
        return input;
    }
};

const domain = extractDomain(input);

const BLACKLISTS = [
    {
        name: 'Spamhaus DBL',
        suffix: 'dbl.spamhaus.org',
        type: 'domain',
        ignoreCodes: ['127.255.255.254', '127.255.255.255'] // Query Refused
    },
    {
        name: 'SURBL',
        suffix: 'multi.surbl.org',
        type: 'domain',
        ignoreCodes: []
    },
    {
        name: 'URIBL',
        suffix: 'multi.uribl.com',
        type: 'domain',
        ignoreCodes: ['127.0.0.1'] // Query Refused
    }
];

const IP_BLACKLISTS = [
    {
        name: 'Spamhaus ZEN',
        suffix: 'zen.spamhaus.org',
        ignoreCodes: ['127.255.255.254', '127.255.255.255'] // Query Refused
    }
];

const writeReport = (status, code, details) => {
    const report = {
        domain: domain,
        status: status,
        details: details,
        timestamp: new Date().toISOString()
    };
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
};

const checkDNS = async (query) => {
    try {
        const addresses = await resolve(query);
        return { listed: true, addresses };
    } catch (err) {
        if (err.code === 'ENOTFOUND') {
            return { listed: false };
        }
        throw err;
    }
};

const reverseIP = (ip) => {
    return ip.split('.').reverse().join('.');
};

const checkAll = async () => {
    console.log(`Checking ${domain} against multiple blacklists...`);

    let results = [];
    let listed = false;
    let details = [];

    // 1. Check Domain-based lists
    for (const list of BLACKLISTS) {
        const query = `${domain}.${list.suffix}`;
        try {
            const result = await checkDNS(query);
            if (result.listed) {
                // Check if any returned code is an "ignore" code (query refused)
                const ignored = result.addresses.filter(addr => list.ignoreCodes.includes(addr));
                const realListings = result.addresses.filter(addr => !list.ignoreCodes.includes(addr));

                if (ignored.length > 0) {
                    console.warn(`[WARN] ${list.name} query refused/blocked (Codes: ${ignored.join(', ')}).`);
                }

                if (realListings.length > 0) {
                    console.error(`[FAIL] ${domain} IS LISTED in ${list.name}! Codes: ${realListings.join(', ')}`);
                    results.push({ source: list.name, listed: true, codes: realListings });
                    details.push(`${list.name}: LISTED (${realListings.join(', ')})`);
                    listed = true;
                }
            } else {
                // console.log(`[PASS] ${domain} is clean on ${list.name}.`);
            }
        } catch (err) {
            console.error(`[ERROR] Check failed for ${list.name}: ${err.message}`);
        }
    }

    // 2. Resolve IP and check IP-based lists
    try {
        const ips = await resolve4(domain);
        if (ips && ips.length > 0) {
            const ip = ips[0]; // Check the first IP
            console.log(`Resolved ${domain} to ${ip}, checking IP blacklists...`);
            const reversedIp = reverseIP(ip);

            for (const list of IP_BLACKLISTS) {
                const query = `${reversedIp}.${list.suffix}`;
                try {
                    const result = await checkDNS(query);
                    if (result.listed) {
                        const ignored = result.addresses.filter(addr => list.ignoreCodes.includes(addr));
                        const realListings = result.addresses.filter(addr => !list.ignoreCodes.includes(addr));

                        if (ignored.length > 0) {
                            console.warn(`[WARN] ${list.name} query refused/blocked (Codes: ${ignored.join(', ')}).`);
                        }

                        if (realListings.length > 0) {
                            console.error(`[FAIL] IP ${ip} IS LISTED in ${list.name}! Codes: ${realListings.join(', ')}`);
                            results.push({ source: list.name, listed: true, codes: realListings, ip: ip });
                            details.push(`${list.name} (IP ${ip}): LISTED (${realListings.join(', ')})`);
                            listed = true;
                        }
                    } else {
                        // console.log(`[PASS] IP ${ip} is clean on ${list.name}.`);
                    }
                } catch (err) {
                    console.error(`[ERROR] Check failed for ${list.name}: ${err.message}`);
                }
            }
        }
    } catch (err) {
        console.warn(`[WARN] Could not resolve IP for ${domain}, skipping IP blacklists: ${err.message}`);
    }

    if (listed) {
        writeReport('listed', 'MULTIPLE', details.join('; '));
        console.log(`\nOverall Status: [FAIL] Domain or IP is listed.`);
        process.exit(1);
    } else {
        writeReport('clean', null, 'Domain and IP not listed in checked blacklists.');
        console.log(`\nOverall Status: [PASS] ${domain} is clean.`);
        process.exit(0);
    }
};

checkAll();
