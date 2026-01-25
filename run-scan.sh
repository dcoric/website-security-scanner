#!/bin/bash
set -e

# 1. Download Assets
echo "[1/4] Starting Asset Download for $TARGET_URL..."
npm run download-assets -- "$TARGET_URL"

# 1.5 Dead Domain Scan
echo "[!] Running Dead Domain Scan..."
node check-dead-domains.js || true
# If this fails (exit 1), we continue so we can report it via email.

# 1.6 Blacklist Scan (Spamhaus, SURBL, URIBL)
echo "[!] Running Blacklist Scan..."
node check-blacklist.js "$TARGET_URL" || true

# 1.7 Safe Browsing Scan
echo "[!] Running Google Safe Browsing Scan..."
node check-safebrowsing.js "$TARGET_URL" || true

# 2. Retire.js Scan
echo "[2/4] Running Vulnerability Scan..."
# We allow this to fail (return code != 0) so the script continues? 
# Usually scan tools return non-zero on findings. We want to proceed to email.
# So we use '|| true' to suppress exit on failure, but we should probably capture exit code if we wanted to fail the container.
# For a cron job reporting email, usually we want it to finish.
REPORTS_DIR="reports"
mkdir -p "$REPORTS_DIR"
npx retire --path js_assets --outputformat json --outputpath "$REPORTS_DIR/retire-report.json" || true

# 3. ClamAV Scan
echo "[3/4] Running ClamAV Scan..."
# Update virus definitions
echo "Updating ClamAV definitions..."
freshclam || echo "Warning: freshclam failed, proceeding with existing definitions."

clamscan -r js_assets > "$REPORTS_DIR/clamav-report.txt" || true
# Cat the report to stdout for logs
cat "$REPORTS_DIR/clamav-report.txt"

# 4. Email Report
echo "[4/4] Sending Report..."
node send-report.js

# 5. Archive Reports
echo "[5/5] Archiving Reports..."
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
# Create archive of all files in REPORTS_DIR (excluding previous archives to avoid recursion if any)
# We cd into REPORTS_DIR to have cleaner paths in archive, or just archive the dir.
# Let's archive the contents of REPORTS_DIR into a file INSIDE REPORTS_DIR.
# We must exclude the archive itself from itself (tar usually handles this warning, but better to be safe)
# Actually, standard practice: scan-report-YYYY-MM-DD_HH-MM-SS.tar.gz
ARCHIVE_NAME="scan-report-${TIMESTAMP}.tar.gz"
tar -czf "$REPORTS_DIR/$ARCHIVE_NAME" -C "$REPORTS_DIR" .

echo "Report archived to $REPORTS_DIR/$ARCHIVE_NAME"

echo "Scan Complete."
