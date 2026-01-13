pipeline {
    agent any

    tools {
        nodejs 'node'
    }

    parameters {
        string(name: 'TARGET_URL', defaultValue: 'https://example.com', description: 'The URL of the website to scan')
    }

    stages {
        stage('Install Dependencies') {
            steps {
                sh 'npm install'
            }
        }

        stage('Gather Assets') {
            steps {
                script {
                    echo "Crawling site and downloading JS assets..."
                    // This script now handles sitemap parsing and crawling
                    sh "npm run download-assets -- ${params.TARGET_URL}"
                }
            }
        }

        stage('Vulnerability Scan') {
            steps {
                script {
                    echo "Running Retire.js on downloaded assets..."
                    sh "mkdir -p reports"
                    // Scan the folder where we downloaded scripts
                    // Return 0 even if issues found so we can mark Unstable manually if needed, 
                    // or let it fail. Retire returns 13 on vuln found by default.
                    try {
                        sh "npx retire --path js_assets --outputformat json --outputpath reports/retire-report.json"
                        // If we want to see output in console too:
                        sh "npx retire --path js_assets"
                    } catch (exc) {
                        currentBuild.result = 'UNSTABLE'
                        echo 'Vulnerabilities detected by Retire.js!'
                    }
                    
                    // Archive the report
                    if (fileExists('reports/retire-report.json')) {
                        archiveArtifacts artifacts: 'reports/retire-report.json'
                    }
                }
            }
        }

        stage('Malware Scan') {
            steps {
                script {
                    // Check if clamscan is available
                    def clamAvExists = sh(script: 'which clamscan', returnStatus: true) == 0
                    if (clamAvExists) {
                        echo "Running ClamAV scan on js_assets/..."
                        try {
                            // -r: recursive, --bell: ring bell on virus
                            sh 'clamscan -r js_assets/'
                        } catch (exc) {
                            currentBuild.result = 'FAILURE'
                            error 'Malware detected by ClamAV!'
                        }
                    } else {
                        echo "ClamAV (clamscan) not found. Skipping malware scan. Assets are saved in workspace/js_assets for manual analysis."
                    }
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
    }
}
