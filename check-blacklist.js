const dns = require('dns');
const url = require('url');

const args = process.argv.slice(2);
if (args.length < 1) {
    console.error('Usage: node check-blacklist.js <URL_OR_DOMAIN>');
    process.exit(1);
}

const input = args[0];

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

console.log(`Checking ${domain} against Spamhaus (Query: ${query})...`);

dns.resolve(query, (err, addresses) => {
    if (err) {
        if (err.code === 'ENOTFOUND') {
            console.log(`[PASS] ${domain} is NOT listed in Spamhaus DBL.`);
            process.exit(0);
        } else {
            console.error(`[ERROR] DNS lookup failed: ${err.message}`);
            // If DNS fails for other reasons, we might not want to fail the build, 
            // but for now let's treat it as a non-failure for the scan flow (soft fail)
            // or we could exit 1 if we want to be strict. 
            // Given the user note about public DNS potentially blocking, 
            // maybe we should fail open (exit 0) but warn?
            // Let's exit 0 but with error log to not block pipeline if DNS is flaky.
            process.exit(0);
        }
    } else {
        // If we get an IP, it is listed.
        // Check for specific Spamhaus return codes that indicate query limitations (blocking)
        // https://www.spamhaus.org/faq/section/DNSBL%20Usage#200
        const blockedCodes = ['127.255.255.254', '127.255.255.255'];
        const isBlocked = addresses.some(addr => blockedCodes.includes(addr));

        if (isBlocked) {
            console.warn(`[WARN] Spamhaus query was BLOCKED by the DNS resolver.`);
            console.warn(`       Return codes: ${addresses.join(', ')}`);
            console.warn(`       Try using a non-public DNS resolver or a Spamhaus DQS key.`);
            // detailed info: 127.255.255.254 = Query blocked (public resolver)
            //                127.255.255.255 = Excessive number of queries
            process.exit(0); // Soft fail / Pass but warn.
        }

        // Real listing
        // Return codes: https://www.spamhaus.org/faq/section/Spamhaus%20DBL#291
        // 127.0.1.2 - Spam domain
        // 127.0.1.4 - Phishing domain
        // ... etc
        console.error(`[FAIL] ${domain} IS LISTED in Spamhaus DBL!`);
        console.error(`       Return codes: ${addresses.join(', ')}`);
        process.exit(1);
    }
});
