# Website Security Scanner

This project automates the security scanning of client-side JavaScript dependencies using `retire-site-scanner`. It is designed to run in a Jenkins pipeline but can also be executed locally.

## Prerequisites

- Node.js (version 16 or higher recommended)
- NPM

## Installation

```bash
npm install
```

## Running Locally

To scan the entire website (using `sitemap.xml`):

1.  **Download Assets**:
    This will crawl the sitemap, visit pages, and save all JavaScript files to `js_assets/`.
    ```bash
    npm run download-assets -- https://example.com
    ```

2.  **Run Vulnerability Scan**:
    Scan the downloaded files using `retire.js`.
    ```bash
    npx retire --path js_assets
    ```

## Jenkins Integration

This repository includes a `Jenkinsfile` that defines a declarative pipeline.

### Pipeline Stages
1.  **Gather Assets**: Crawls the site via sitemap and downloads scripts.
2.  **Vulnerability Scan**: Runs `retire.js` on the assets.
3.  **Malware Scan**: Runs `clamscan` (if available).

## Malware Analysis & False Positives

If your antivirus (e.g., Bitdefender) detects "malware" in your Javascript files, it might be a false positive caused by code obfuscation. To investigate:

1.  **Download the Scripts**:
    Run the downloader to fetch all scripts loaded by the site into a local `js_assets` folder.
    ```bash
    npm run download-assets -- https://example.com
    ```

2.  **Inspect or Scan**:
## Docker & Cron Usage

To run this scanner as a containerized job with email reporting:

1.  **Configuration**:
    Edit `docker-compose.yml` or export environment variables for your SMTP settings.
    ```yaml
    environment:
      - TARGET_URL=https://example.com
      - SMTP_HOST=smtp.gmail.com
      - SMTP_USER=your_email@gmail.com
      - SMTP_PASS=your_app_password
      - EMAIL_TO=recipient@example.com
      
      # LLM Integration (Optional) - Generates AI-written email reports
      - LLM_PROVIDER=deepseek # or openai, gemini, custom
      - LLM_API_KEY=your_key_here
      - LLM_MODEL=deepseek-chat
    ```

2.  **Build & Run**:
    ```bash
    docker compose build
    docker compose up
    ```

3.  **Run as Cron Job**:
    To schedule this to run every Sunday at 9 AM, add the following to your server's crontab (`crontab -e`):
    ```bash
    0 9 * * 0 cd /path/to/security-scan && docker compose up >> /var/log/security-scan.log 2>&1
    ```

### What happens inside the container?
1.  **Assets Download**: Crawls sitemap and downloads scripts.
2.  **Vulnerability Scan**: Runs `retire.js`.
3.  **Malware Scan**: Runs `clamscan` (detected false positives will be listed).

