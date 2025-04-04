# ✨ M.A.I.L-Sentinel – My Artificial Intelligence Log Sentinel ✨

M.A.I.L-Sentinel is not just a log monitoring script; it’s an intelligent guardian created to scan, filter, and analyze Postfix log data. Inspired by the need for a smarter, self-aware sentinel over your email logs, M.A.I.L-Sentinel leverages AI to provide actionable recommendations for error resolution, ensuring your email infrastructure remains robust and secure.

## Requirements ✅

- Bash shell
- Command line utilities: jq, curl, tac, mail, sendmail, awk, sed.
- Environment variables:
  - `POSTFIX_REPORT_EMAIL`: Recipient email address ✉️.
  - `OPENAI_API_KEY`: Valid OpenAI API key 🔑.

## Configuration ⚙️

Create a secure configuration file (`config.sh`) in the project directory with your environment variables. For example:

```bash
# Secure configuration file for the Postfix Error Report Script.
# Ensure this file is only readable by the owner (e.g., chmod 600).
export POSTFIX_REPORT_EMAIL="user@example.com"  # Recipient email ✉️
export OPENAI_API_KEY="your_secure_openai_api_key"  # API key 🔑
```

## Usage 🚀

1. Ensure that `config.sh` exists and has the correct permissions.
2. Run the script manually:
   ```bash
   ./MAIL-Sentinel.sh
   ```
3. (Optional) To run as a cronjob, add a line similar to:
   ```cron
   0 * * * * ~/scripts/MAIL-Sentinel/MAIL-Sentinel.sh
   ```

## Security Best Practices 🔒

- Do not commit `config.sh` or any files containing sensitive information to version control.
- Use `.gitignore` to prevent accidental commits of sensitive files.
