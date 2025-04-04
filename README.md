# ✨ Postfix Error Report ✨

This bash script scans Postfix log files for specific error patterns and sends email notifications with an HTML report. 📈 For errors with multiple occurrences, it generates recommendations using the OpenAI API (with a rate limit of 5 API calls per execution). 🚀

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
   ./postfix_error_report.sh
   ```
3. (Optional) To run as a cronjob, add a line similar to:
   ```cron
   0 * * * * ~/scripts/postfix_error_report/postfix_error_report.sh
   ```

## Security Best Practices 🔒

- Do not commit `config.sh` or any files containing sensitive information to version control.
- Use `.gitignore` to prevent accidental commits of sensitive files.
