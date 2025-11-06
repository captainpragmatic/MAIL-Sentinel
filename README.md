# ✨ M.A.I.L. Sentinel – My Artificial Intelligence Log Sentinel ✨

M.A.I.L. Sentinel is not just a log monitoring script; it's an intelligent guardian created to scan, filter, and analyze Postfix log data. Inspired by the need for a smarter, self-aware sentinel over your email logs, M.A.I.L. Sentinel leverages AI to provide actionable recommendations for error resolution, ensuring your email infrastructure remains robust and secure.

## 🎯 Key Features

- **🤖 AI-Powered Analysis**: Uses OpenAI to generate actionable recommendations for recurring errors
- **📊 Executive Summary**: Get an at-a-glance view of critical, warning, and informational issues
- **🎨 Beautiful HTML Reports**: Modern, responsive email reports with color-coded severity levels
- **🔍 IP Intelligence**: Automatic hostname, ASN, and country lookup for error sources
- **⚡ Copy-Paste Commands**: Ready-to-run commands for investigating and fixing issues
- **📌 Decision Guides**: Step-by-step guidance for common error types
- **✅ Action Checklists**: Clear next steps for each error category
- **🎚️ Severity Classification**: Automatic categorization (Critical/Warning/Info)
- **🔇 Smart Noise Filtering**: Configurable whitelisting of known safe patterns
- **⚙️ Fully Configurable**: Customizable thresholds, API limits, and time windows

## Requirements ✅

- Bash shell
- Command line utilities: jq, curl, tac, mail, sendmail, awk, sed, host, whois, timeout.
- Environment variables:
  - `POSTFIX_REPORT_EMAIL`: Recipient email address ✉️.
  - `OPENAI_API_KEY`: Valid OpenAI API key 🔑.

## Configuration ⚙️

Create a secure configuration file (`config.sh`) in the project directory with your environment variables. You can copy `config.sh.example` as a starting point:

```bash
cp config.sh.example config.sh
chmod 600 config.sh
```

### Required Configuration

```bash
export POSTFIX_REPORT_EMAIL="user@example.com"  # Recipient email ✉️
export OPENAI_API_KEY="your_secure_openai_api_key"  # API key 🔑
```

### Optional Configuration (with defaults)

```bash
# Thresholds and Limits
export ERROR_THRESHOLD=5           # Min error count before sending to OpenAI (default: 5)
export API_CALL_LIMIT=5           # Max API calls per execution (default: 5)
export TIME_WINDOW_HOURS=24       # Hours of logs to analyze (default: 24)
export MAX_API_TIMEOUT=30         # OpenAI API timeout in seconds (default: 30)
export AUTO_IGNORE_THRESHOLD=3    # Ignore IPs with fewer errors (default: 3)

# Debug Mode
export MAIL_SENTINEL_DEBUG=false  # Set to true for verbose output

# Known Safe Patterns (pipe-separated, categorized as INFO)
export KNOWN_SAFE_PATTERNS="gaia.bounces.google.com|amazonses.com|mailgun.net"
```

## Usage 🚀

1. **Quick Installation**: Run the interactive installer:
   ```bash
   ./install.sh
   ```
   This will guide you through configuration and optional cron job setup.

2. **Manual Setup**:
   - Ensure that `config.sh` exists and has the correct permissions.
   - Run the script manually:
   ```bash
   ./MAIL-Sentinel.sh
   ```

3. **Scheduled Execution**: To run as a cronjob, add a line similar to:
   ```cron
   0 * * * * ~/scripts/MAIL-Sentinel/MAIL-Sentinel.sh
   ```

## 📧 Report Features

M.A.I.L. Sentinel generates comprehensive HTML email reports with:

### Executive Summary
- **Severity Counts**: Visual dashboard showing Critical, Warning, and Info issue counts
- **Recommended Actions**: Prioritized list of what to do first
- **Quick Overview**: Understand the health of your mail server at a glance

### Detailed Error Cards
Each error above the threshold gets a detailed card containing:

1. **Severity Badge**: Color-coded (🔴 Critical, 🟡 Warning, 🟢 Info)
2. **Error Details**: Full error message and occurrence count
3. **IP Intelligence**:
   - Hostname lookup
   - ASN (Autonomous System Number)
   - Country of origin
4. **AI Recommendation**: Smart analysis from OpenAI on how to fix the issue
5. **Decision Guide**: Step-by-step questions to help you decide what action to take
6. **Actionable Commands**: Copy-paste ready commands to investigate and fix issues
7. **Action Checklist**: Clear next steps for resolution

### Severity Levels Explained

- **🔴 CRITICAL**: Requires immediate attention (authentication failures, service disruptions, disk full, fatal errors)
- **🟡 WARNING**: Should be investigated (SSL errors with >10 occurrences, connection issues, bounces)
- **🟢 INFO**: Normal noise or known safe patterns (low-count errors, whitelisted services like Google Bounces)

## Security Best Practices 🔒

- Do not commit `config.sh` or any files containing sensitive information to version control.
- Use `.gitignore` to prevent accidental commits of sensitive files.
- Keep your `config.sh` file permissions set to 600 (readable only by owner).
- Regularly review and update your `KNOWN_SAFE_PATTERNS` to reduce noise in reports.
