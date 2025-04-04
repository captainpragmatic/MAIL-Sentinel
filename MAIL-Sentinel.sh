#!/bin/bash
# ###############################################################
# M.A.I.L. Sentinel – My Artificial Intelligence Log Sentinel
#
# Description:
#   Inspired by the need for a smarter, self-aware guardian over your Postfix logs,
#   M.A.I.L. Sentinel was born. It's not just a log monitoring script—it's an intelligent
#   guardian that scans, filters, and analyzes Postfix log data using AI to provide actionable
#   recommendations on error resolution, ensuring your email infrastructure remains robust and secure.
#
#   If errors are detected:
#     - When send_immediately=true: Each error is emailed individually.
#     - When send_immediately=false: All errors are aggregated and a single
#       HTML email report is sent.
#
#   For errors with multiple occurrences, a recommendation is generated using
#   the OpenAI API (with a rate limit of 5 API calls per execution) via the
#   get_fix_recommendation() function.
#
# Requirements:
#   - Environment variable POSTFIX_REPORT_EMAIL must be set with the recipient's
#     email address.
#   - Environment variable OPENAI_API_KEY must be set with a valid OpenAI API key.
#   - Command line utilities: jq, curl, tac, sendmail, awk, sed.
#
# Usage:
#   1. Set the required environment variables, for example:
#        export POSTFIX_REPORT_EMAIL="user@example.com"
#        export OPENAI_API_KEY="your_openai_api_key"
#   2. Run the script:
#        ./MAIL-Sentinel.sh
#   3. (Optional) To run as a cronjob, add a line similar to:
#        0 * * * * /root/scripts/MAIL-Sentinel/MAIL-Sentinel.sh
#
# Options:
#   - send_immediately: Set to true to send an email immediately for each error instead
#     of aggregating them into a single summary.
#
# ###############################################################
# set -euo pipefailil
# Source secure configuration if it exists.
# shellcheck disable=SC1091
[ -f "$(dirname "$0")/config.sh" ] && source "$(dirname "$0")/config.sh"

# Validate required external commands are installed.
required_cmds=("jq" "curl" "tac" "mail" "sendmail" "awk" "sed")
for cmd in "${required_cmds[@]}"; do
    if ! command -v "$cmd" > /dev/null; then
        echo "Error: Required command '$cmd' is not installed." >&2
        exit 1
    fi
done

# Option: set send_immediately to true to send an email for each matching line.
send_immediately=false

# Email to notify - this should be set in the environment
email="${POSTFIX_REPORT_EMAIL}"
if [[ -z "$email" ]]; then
    echo "Error: POSTFIX_REPORT_EMAIL environment variable is not set." >&2
    exit 1
fi

# Check if OPENAI_API_KEY is set
if [[ -z "$OPENAI_API_KEY" ]]; then
    echo "Error: OPENAI_API_KEY environment variable is not set." >&2
    exit 1
fi

# Pattern to flag errors
pattern="NOQUEUE|bounced|deferred|error|bounce|failed"

# Single regex for ignored patterns
ignored_pattern="SASL LOGIN|SSL_accept\\(\\)"

# List of log files to scan
logfiles=( "/var/log/mail.log" "/var/log/mail.err" "/var/log/procmail.log" )

# Arrays for collecting full error lines and for grouping by IP
errors=()
declare -A ip_errors_count
declare -A ip_errors_sample

# Calculate epoch for 24 hours ago
cutoff_epoch=$(date --date="24 hours ago" +%s)

# Global counter for API calls
declare -g __get_fix_recommendation_api_call_count=0

# New function to call OpenAI API for recommendations with in-memory rate limiting and debug logging
get_fix_recommendation() {
    local error_summary="$1"
    echo "DEBUG: Entering get_fix_recommendation with summary: $error_summary" >&2

    if ((__get_fix_recommendation_api_call_count >= 3)); then
        echo "DEBUG: API call count limit reached: $__get_fix_recommendation_api_call_count" >&2
        echo "Recommendation unavailable: API rate limit reached."
        return
    fi
    
    ((__get_fix_recommendation_api_call_count++))

    local prompt="Summarize the following Postfix error in a concise bullet-point list with three recommendations on how to fix, prevent, or ignore it (max 200 words): \"$error_summary\"."

    # Build a safe JSON payload using jq
    local payload
    payload=$(jq -n --arg model "gpt-4o-mini" --arg prompt "$prompt" '{
                        model: $model,
                        messages: [{role: "user", content: $prompt}],
                        max_tokens: 200,
                        temperature: 0.4
                    }')

    # Call OpenAI API with a maximum time of 30 seconds
    local response
    response=$(curl --max-time 30 -s https://api.openai.com/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d "$payload" 2>/dev/null)

    local curl_exit_code=$?
    if [ $curl_exit_code -ne 0 ] || [ -z "$response" ]; then
        echo "DEBUG: API call failed with exit code $curl_exit_code" >&2
        echo "Recommendation unavailable at this time."
        return
    fi

    # Extract recommendation using jq
    local rec
    rec=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)

    if [ -z "$rec" ] || [ "$rec" = "null" ]; then
        echo "Recommendation unavailable at this time."
    else
        echo "$rec" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
    fi
}

# Process each logfile in the defined logfiles list
for logfile in "${logfiles[@]}"; do
    [[ -f "$logfile" ]] || continue
    # Replace the while read loop with a mapfile loop to avoid subshell side effects:
    mapfile -t lines < <(tac "$logfile")
    for line in "${lines[@]}"; do
        # Extract timestamp and pre-process it (using the first field only)
        ts=$(echo "$line" | awk '{print $1}')
        if [[ "$ts" =~ ^Time: ]]; then
            # Handle log entries with "Time:" prefix; remove the prefix to use the epoch value directly.
            log_epoch="${ts#Time:}"
        else
            ts_fixed=$(echo "$ts" | sed -E 's/\.[0-9]+//; s/([+-][0-9]{2}):([0-9]{2})/\1\2/')
            log_epoch=$(date --date="$ts_fixed" +%s 2>/dev/null || true)
        fi
        if [[ -z "$log_epoch" ]]; then
            echo "Warning: Failed to convert timestamp from line: $line" >&2
            continue
        fi
        if [ "$log_epoch" -lt "$cutoff_epoch" ]; then
            break
        fi

        # Skip lines matching the ignored patterns
        if echo "$line" | grep -Ei "$ignored_pattern" >/dev/null; then
            continue
        fi

        # Check if the line contains flagged patterns
        if echo "$line" | grep -Ei "$pattern" >/dev/null; then
            # Extract remote IP using primary regex (assuming it is preceded by "rip=")
            ip=$(echo "$line" | grep -oP 'rip=\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
            if [ -z "$ip" ]; then
                # Fallback: extract the first valid IPv4 address found in the line
                candidate=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1 || true)
                if [ -n "$candidate" ]; then
                    ip="$candidate"
                else
                    ip="unknown"
                fi
            fi

            # Remove the timestamp for a uniform summary message
            sample_msg=$(echo "$line" | cut -d' ' -f2-)
            
            # Group errors by IP: count occurrences and keep one sample message per IP
            ip_errors_count["$ip"]=$(( ${ip_errors_count["$ip"]:-0} + 1 ))
            if [ "${ip_errors_count["$ip"]}" -eq 1 ]; then
                ip_errors_sample["$ip"]="$sample_msg"
            fi

            if [ "$send_immediately" = true ]; then
                # Send email immediately using sendmail
                {
                    echo "Subject: M.A.I.L-Sentinel Report for $(date)"
                    echo "MIME-Version: 1.0"
                    echo "Content-Type: text/plain; charset=UTF-8"
                    echo
                    echo "$line"
                } | sendmail "$email"
                echo "Email sent for line: $line"
            else
                # Add the error line to grouped errors for later summary
                errors+=("$line")
            fi
        fi
    done
    # After processing a logfile, print how many errors were found
    echo "Found ${#errors[@]} error(s) in $logfile" >&2
done

if [ "$send_immediately" = false ] && (( ${#errors[@]} > 0 )); then
    # Build the HTML email body for aggregated errors:
    email_body=$(cat <<EOF
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>M.A.I.L-Sentinel Report on $(hostname)</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f2f2f2; }
    .container { max-width: 800px; margin: auto; background: #ffffff; padding: 20px; border-radius: 5px; }
    h1 { color: #333333; }
    h3 { color: #555555; }
    .error { background-color: #ffe6e6; padding: 10px; border-left: 5px solid #ff4d4d; }
    .recommendation { background-color: #e6f2ff; padding: 10px; border-left: 5px solid #4d94ff; white-space: pre-wrap; }
    hr { border: 0; border-top: 1px solid #dddddd; margin: 20px 0; }
    pre { margin: 0; white-space: pre-wrap; font-family: inherit; }
  </style>
</head>
<body>
<div class="container">
  <h1>M.A.I.L-Sentinel Report on $(hostname) for $(date)</h1>
  <h3>Error Summary</h3>
EOF
)

    # Use a local counter within the loop to limit API calls
    api_call_count=0
    echo "DEBUG: Starting aggregated loop; total groups: ${#ip_errors_count[@]}" >&2
    for ip in "${!ip_errors_count[@]}"; do
        count=${ip_errors_count[$ip]}
        sample_msg=${ip_errors_sample[$ip]}
        if [ "$count" -gt 3 ]; then
            summary_line="$ip: $sample_msg (occurred $count times)"
            if [ $api_call_count -lt 5 ]; then
                echo "DEBUG: Making API call for: $summary_line" >&2
                recommendation=$(get_fix_recommendation "$summary_line")
                echo "DEBUG: Incrementing api_call_count." >&2
                ((api_call_count++))
                echo "DEBUG: api_call_count is now: $api_call_count" >&2
            else
                recommendation="Recommendation unavailable: API rate limit reached."
            fi
            email_body+=$(cat <<EOF

<div class="error"><strong>${summary_line}</strong><br>
<div class="recommendation"><strong>Recommendation:</strong><br><pre>${recommendation}</pre></div></div><br>
EOF
)
            echo "DEBUG: Added group for IP $ip" >&2
        fi
    done
    echo "DEBUG: Finished aggregated loop. Total API calls made: $api_call_count" >&2

    # Add debug output to indicate the loop completed
    echo "DEBUG: Finished processing aggregated error groups. Total API calls made: $api_call_count" >&2

    email_body+=$(cat <<'EOF'
<hr><h3>Full Log Errors</h3>
EOF
)
    # Append each full error log entry
    for err in "${errors[@]}"; do
        email_body+=$(cat <<EOF
<p class="error">${err}</p>
EOF
)
    done
    email_body+=$(cat <<'EOF'
  <hr>
  <p>This is an automated email, please do not reply directly to this message.</p>
</div>
</body>
</html>
EOF
)
    
    # Log that email is about to be sent
    echo "DEBUG: Sending aggregated email." >&2
    {
        echo "Subject: M.A.I.L-Sentinel Report on $(hostname) for $(date)"
        echo "MIME-Version: 1.0"
        echo "Content-Type: text/html; charset=UTF-8"
        echo
        echo "$email_body"
    } | sendmail "$email"
    echo "DEBUG: Aggregated email sent." >&2
fi
