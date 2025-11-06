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
set -euo pipefail

# Trap to detect unexpected termination (only on errors)
trap 'echo "✗ FATAL: Script terminated unexpectedly at line $LINENO with exit code $?" >&2' ERR

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
declare -A ip_errors_severity
declare -A ip_intelligence_cache

# Severity counters for executive summary
critical_count=0
warning_count=0
info_count=0

# Calculate epoch for 24 hours ago
cutoff_epoch=$(date --date="24 hours ago" +%s)

# Global counter for API calls
declare -g __get_fix_recommendation_api_call_count=0

# Configuration defaults (can be overridden in config.sh)
ERROR_THRESHOLD=${ERROR_THRESHOLD:-5}
API_CALL_LIMIT=${API_CALL_LIMIT:-5}
TIME_WINDOW_HOURS=${TIME_WINDOW_HOURS:-24}
MAX_API_TIMEOUT=${MAX_API_TIMEOUT:-30}
AUTO_IGNORE_THRESHOLD=${AUTO_IGNORE_THRESHOLD:-3}
MAIL_SENTINEL_DEBUG=${MAIL_SENTINEL_DEBUG:-false}
KNOWN_SAFE_PATTERNS=${KNOWN_SAFE_PATTERNS:-"gaia.bounces.google.com|amazonses.com|mailgun.net|sendgrid.net"}

# Helper function for debug logging
debug_log() {
    if [ "$MAIL_SENTINEL_DEBUG" = true ]; then
        echo "DEBUG: $*" >&2
    fi
}

# New function to call OpenAI API for recommendations with in-memory rate limiting and debug logging
get_fix_recommendation() {
    local error_summary="$1"
    debug_log "Entering get_fix_recommendation with summary: $error_summary"

    if ((__get_fix_recommendation_api_call_count >= API_CALL_LIMIT)); then
        debug_log "API call count limit reached: $__get_fix_recommendation_api_call_count"
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

    # Call OpenAI API with a maximum time configured via MAX_API_TIMEOUT
    local response
    response=$(curl --max-time "$MAX_API_TIMEOUT" -s https://api.openai.com/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d "$payload" 2>/dev/null)

    local curl_exit_code=$?
    if [ $curl_exit_code -ne 0 ] || [ -z "$response" ]; then
        debug_log "API call failed with exit code $curl_exit_code"
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

# Get IP intelligence information (hostname, ASN, etc.)
get_ip_intelligence() {
    local ip="$1"
    local hostname="unknown"
    local asn="unknown"
    local country="unknown"

    if [ "$ip" = "unknown" ]; then
        echo "Unknown IP"
        return
    fi

    # Try to get hostname
    hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//' || echo "unknown")

    # Try to get ASN and country info from a simple whois lookup
    local whois_output
    whois_output=$(timeout 5 whois "$ip" 2>/dev/null || echo "")

    if [ -n "$whois_output" ]; then
        asn=$(echo "$whois_output" | grep -iE "^(origin|originas):" | head -1 | awk '{print $NF}' || echo "unknown")
        country=$(echo "$whois_output" | grep -i "^country:" | head -1 | awk '{print $NF}' || echo "unknown")
    fi

    echo "$hostname|$asn|$country"
}

# Categorize error severity
categorize_severity() {
    local error_line="$1"
    local count="$2"

    debug_log "categorize_severity called with count=$count"

    # Check if it matches known safe patterns (INFO level)
    if echo "$error_line" | grep -qE "$KNOWN_SAFE_PATTERNS"; then
        debug_log "Matched KNOWN_SAFE_PATTERNS"
        echo "INFO"
        return
    fi

    # Critical: authentication failures, service disruptions, delivery failures
    if echo "$error_line" | grep -qiE "authentication failed|service unavailable|queue file write error|disk full|fatal"; then
        debug_log "Matched CRITICAL pattern"
        echo "CRITICAL"
        return
    fi

    # Warning: SSL errors, connection issues, bounces, deferred
    if echo "$error_line" | grep -qiE "SSL_accept|TLS|connection reset|bounced|deferred|timeout"; then
        debug_log "Matched WARNING/INFO pattern"
        if [ "$count" -gt 10 ]; then
            echo "WARNING"
        else
            echo "INFO"
        fi
        return
    fi

    # Default to INFO for low-count errors
    debug_log "Using default severity logic"
    if [ "$count" -le "$AUTO_IGNORE_THRESHOLD" ]; then
        echo "INFO"
    else
        echo "WARNING"
    fi
}

# Generate specific command suggestions based on error type
get_command_suggestions() {
    local error_line="$1"
    local ip="$2"
    local commands=""

    if echo "$error_line" | grep -qiE "SSL_accept|TLS"; then
        commands+="# Test SSL certificate:\n"
        commands+="echo | openssl s_client -connect \$(hostname):25 -starttls smtp 2>/dev/null | openssl x509 -noout -dates\n\n"
        commands+="# Check certificate expiry:\n"
        commands+="echo | openssl s_client -connect \$(hostname):25 -starttls smtp 2>/dev/null | openssl x509 -noout -enddate\n\n"
        commands+="# View current TLS settings:\n"
        commands+="postconf smtpd_tls_security_level smtpd_tls_protocols\n\n"
    fi

    if echo "$error_line" | grep -qiE "connection reset|refused|timeout"; then
        commands+="# Check if IP is on blocklists:\n"
        commands+="# Visit: https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a$ip\n\n"
        commands+="# Block this IP with fail2ban (if malicious):\n"
        commands+="fail2ban-client set postfix banip $ip\n\n"
        commands+="# Or block with UFW:\n"
        commands+="ufw deny from $ip\n\n"
    fi

    if echo "$error_line" | grep -qiE "authentication failed"; then
        commands+="# Review authentication logs:\n"
        commands+="grep '$ip' /var/log/mail.log | grep -i auth\n\n"
        commands+="# Check SASL configuration:\n"
        commands+="postconf smtpd_sasl_auth_enable smtpd_sasl_security_options\n\n"
    fi

    if [ -z "$commands" ]; then
        commands="# Review full log context:\ngrep '$ip' /var/log/mail.log | tail -20\n"
    fi

    echo -e "$commands"
}

# Generate decision guide for error type
get_decision_guide() {
    local error_line="$1"

    if echo "$error_line" | grep -qiE "SSL_accept|TLS"; then
        cat <<'EOF'
<strong>📌 DECISION GUIDE FOR SSL/TLS ERRORS:</strong>
<ol style="margin: 10px 0; padding-left: 20px;">
<li><strong>Q1:</strong> Is the IP from a known mail provider (Gmail, Outlook, etc.)?
  <ul><li><strong>YES</strong> → Your SSL cert may be expired or misconfigured. Check cert validity.</li>
  <li><strong>NO</strong> → Go to Q2</li></ul></li>
<li><strong>Q2:</strong> Are there successful TLS connections from other IPs?
  <ul><li><strong>YES</strong> → This IP may be using outdated SSL/TLS version or is malicious scanner.</li>
  <li><strong>NO</strong> → Your mail server SSL config is broken. Fix immediately!</li></ul></li>
<li><strong>Q3:</strong> Error count > 10 in 24h from same IP?
  <ul><li><strong>YES</strong> → Likely a scanner. Consider blocking the IP.</li>
  <li><strong>NO</strong> → Normal background noise. Monitor but no action needed.</li></ul></li>
</ol>
EOF
    elif echo "$error_line" | grep -qiE "connection reset|refused"; then
        cat <<'EOF'
<strong>📌 DECISION GUIDE FOR CONNECTION ERRORS:</strong>
<ol style="margin: 10px 0; padding-left: 20px;">
<li><strong>Q1:</strong> Is this IP on public blocklists?
  <ul><li><strong>YES</strong> → Known malicious. Block immediately with fail2ban.</li>
  <li><strong>NO</strong> → Go to Q2</li></ul></li>
<li><strong>Q2:</strong> Do you recognize the hostname/company?
  <ul><li><strong>YES</strong> → May be a legitimate service with network issues. Whitelist if trusted.</li>
  <li><strong>NO</strong> → Likely scanning activity. Monitor or block.</li></ul></li>
<li><strong>Q3:</strong> Is the error frequency increasing?
  <ul><li><strong>YES</strong> → Active attack/scan. Enable rate limiting and blocking.</li>
  <li><strong>NO</strong> → One-off issue. No action needed.</li></ul></li>
</ol>
EOF
    else
        cat <<'EOF'
<strong>📌 DECISION GUIDE:</strong>
<ol style="margin: 10px 0; padding-left: 20px;">
<li>Check if the error source is from a known/trusted service</li>
<li>Review the error context in full logs</li>
<li>If repeated (>10x): investigate and take action</li>
<li>If isolated (<3x): monitor but likely safe to ignore</li>
</ol>
EOF
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
                # Categorize severity for this IP (will be updated later based on final count)
                severity=$(categorize_severity "$sample_msg" "${ip_errors_count["$ip"]}")
                ip_errors_severity["$ip"]="$severity"
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
    {
        echo "✓ CHECKPOINT: Found ${#errors[@]} total errors from ${#ip_errors_count[@]} unique IPs"
        echo "✓ CHECKPOINT: Starting severity categorization at $(date '+%H:%M:%S')..."
    } >&2
    # Recategorize severity based on final counts and count by severity
    echo "✓ CHECKPOINT: About to start loop over ${#ip_errors_count[@]} IPs..." >&2
    ip_counter=0
    echo "✓ CHECKPOINT: ip_counter initialized, entering loop..." >&2
    for ip in "${!ip_errors_count[@]}"; do
        ((++ip_counter))
        echo "  → [$(date '+%H:%M:%S')] Processing IP $ip_counter/${#ip_errors_count[@]}: $ip" >&2
        count=${ip_errors_count[$ip]:-0}
        sample_msg=${ip_errors_sample[$ip]:-"No sample message"}

        echo "    Count: $count, calling categorize_severity..." >&2
        severity=$(categorize_severity "$sample_msg" "$count" 2>&1) || {
            echo "    ✗ ERROR: categorize_severity failed for IP $ip" >&2
            severity="INFO"
        }
        echo "    Severity: $severity" >&2

        ip_errors_severity["$ip"]="$severity"

        case "$severity" in
            CRITICAL) ((critical_count++)) ;;
            WARNING) ((warning_count++)) ;;
            INFO) ((info_count++)) ;;
        esac
    done
    echo "✓ CHECKPOINT: Severity categorization complete - Critical: $critical_count, Warning: $warning_count, Info: $info_count" >&2

    # Build the HTML email body for aggregated errors:
    echo "✓ CHECKPOINT: Building email body..." >&2
    email_body=$(cat <<EOF
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>M.A.I.L-Sentinel Report on $(hostname)</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f5f5f5; }
    .container { max-width: 900px; margin: auto; background: #ffffff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { color: #2c3e50; margin-bottom: 5px; }
    h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-top: 30px; }
    h3 { color: #555555; margin-top: 20px; }
    .header-date { color: #7f8c8d; font-size: 14px; margin-bottom: 20px; }
    .exec-summary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
    .exec-summary h2 { color: white; border-bottom: 2px solid rgba(255,255,255,0.3); margin-top: 0; }
    .severity-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 15px 0; }
    .severity-box { text-align: center; padding: 15px; border-radius: 5px; font-weight: bold; }
    .severity-critical { background-color: #e74c3c; color: white; }
    .severity-warning { background-color: #f39c12; color: white; }
    .severity-info { background-color: #3498db; color: white; }
    .severity-count { font-size: 32px; display: block; margin-bottom: 5px; }
    .action-list { background-color: rgba(255,255,255,0.2); padding: 15px; border-radius: 5px; margin-top: 15px; }
    .action-list ul { margin: 5px 0; padding-left: 20px; }
    .error-card { background-color: #fff; border: 1px solid #ddd; border-left: 5px solid #e74c3c; padding: 15px; margin: 15px 0; border-radius: 5px; }
    .error-card.warning { border-left-color: #f39c12; }
    .error-card.info { border-left-color: #3498db; }
    .error-header { font-weight: bold; color: #2c3e50; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
    .severity-badge { padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
    .badge-critical { background-color: #e74c3c; color: white; }
    .badge-warning { background-color: #f39c12; color: white; }
    .badge-info { background-color: #3498db; color: white; }
    .ip-intel { background-color: #ecf0f1; padding: 10px; border-radius: 5px; font-size: 13px; margin: 10px 0; font-family: 'Courier New', monospace; }
    .recommendation { background-color: #e8f4f8; padding: 15px; border-left: 5px solid #3498db; border-radius: 5px; margin: 10px 0; }
    .commands { background-color: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; font-family: 'Courier New', monospace; font-size: 13px; white-space: pre-wrap; overflow-x: auto; }
    .decision-guide { background-color: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; margin: 10px 0; }
    .checklist { list-style-type: none; padding-left: 0; }
    .checklist li { padding: 5px 0; }
    .checklist li:before { content: "☐ "; font-size: 18px; margin-right: 8px; }
    hr { border: 0; border-top: 1px solid #dddddd; margin: 30px 0; }
    .full-logs { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
    .log-entry { font-family: 'Courier New', monospace; font-size: 12px; padding: 8px; background-color: #fff; border: 1px solid #dee2e6; border-radius: 3px; margin: 5px 0; word-wrap: break-word; }
    .footer { text-align: center; color: #7f8c8d; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }
  </style>
</head>
<body>
<div class="container">
  <h1>🛡️ M.A.I.L-Sentinel Report</h1>
  <div class="header-date">Host: <strong>$(hostname)</strong> | Report Generated: <strong>$(date '+%Y-%m-%d %H:%M:%S %Z')</strong></div>

  <div class="exec-summary">
    <h2>📊 Executive Summary</h2>
    <div class="severity-grid">
      <div class="severity-box severity-critical">
        <span class="severity-count">$critical_count</span>
        <span>🔴 CRITICAL</span>
      </div>
      <div class="severity-box severity-warning">
        <span class="severity-count">$warning_count</span>
        <span>🟡 WARNING</span>
      </div>
      <div class="severity-box severity-info">
        <span class="severity-count">$info_count</span>
        <span>🟢 INFO</span>
      </div>
    </div>
    <div class="action-list">
      <strong>⚡ RECOMMENDED ACTIONS:</strong>
      <ul>
EOF
)

    # Add dynamic recommendations to executive summary
    if [ "$critical_count" -gt 0 ]; then
        email_body+="<li>🔴 <strong>URGENT:</strong> $critical_count critical issue(s) requiring immediate attention</li>"
    fi
    if [ "$warning_count" -gt 0 ]; then
        email_body+="<li>🟡 Review $warning_count warning(s) and take action if needed</li>"
    fi
    if [ "$info_count" -gt 0 ]; then
        email_body+="<li>🟢 $info_count informational item(s) detected (likely normal traffic)</li>"
    fi

    email_body+=$(cat <<EOF

      </ul>
    </div>
  </div>

  <h2>🔍 Detailed Error Analysis</h2>
EOF
)
    echo "✓ CHECKPOINT: Initial email body built successfully" >&2

    # Use a local counter within the loop to limit API calls
    api_call_count=0
    debug_log "Starting aggregated loop; total groups: ${#ip_errors_count[@]}"
    echo "✓ CHECKPOINT: Processing ${#ip_errors_count[@]} unique IPs for detailed analysis..." >&2

    # Sort IPs by severity (Critical, Warning, Info) then by count
    declare -a critical_ips warning_ips info_ips
    for ip in "${!ip_errors_count[@]}"; do
        severity=${ip_errors_severity[$ip]}
        case "$severity" in
            CRITICAL) critical_ips+=("$ip") ;;
            WARNING) warning_ips+=("$ip") ;;
            INFO) info_ips+=("$ip") ;;
        esac
    done

    # Process all IPs in order of severity
    detailed_cards_added=0
    for ip in "${critical_ips[@]}" "${warning_ips[@]}" "${info_ips[@]}"; do
        [ -z "$ip" ] && continue
        count=${ip_errors_count[$ip]}
        sample_msg=${ip_errors_sample[$ip]}
        severity=${ip_errors_severity[$ip]}

        # Only include errors at or above the threshold
        if [ "$count" -ge "$ERROR_THRESHOLD" ]; then
            ((detailed_cards_added++))
            summary_line="$ip: $sample_msg (occurred $count times)"

            # Determine card CSS class based on severity
            case "$severity" in
                CRITICAL) card_class="error-card" badge_class="badge-critical" ;;
                WARNING) card_class="error-card warning" badge_class="badge-warning" ;;
                INFO) card_class="error-card info" badge_class="badge-info" ;;
                *) card_class="error-card" badge_class="badge-warning" ;;
            esac

            # Get IP intelligence
            if [ -n "${ip_intelligence_cache[$ip]}" ]; then
                ip_intel="${ip_intelligence_cache[$ip]}"
            else
                ip_intel=$(get_ip_intelligence "$ip")
                ip_intelligence_cache["$ip"]="$ip_intel"
            fi
            IFS='|' read -r hostname asn country <<< "$ip_intel"

            # Get AI recommendation if within limit
            if [ $api_call_count -lt "$API_CALL_LIMIT" ]; then
                debug_log "Making API call for: $summary_line"
                recommendation=$(get_fix_recommendation "$summary_line")
                ((api_call_count++))
                debug_log "api_call_count is now: $api_call_count"
            else
                recommendation="⚠️ Recommendation unavailable: API rate limit reached ($API_CALL_LIMIT max per report)."
            fi

            # Get command suggestions and decision guide
            commands=$(get_command_suggestions "$sample_msg" "$ip")
            decision_guide=$(get_decision_guide "$sample_msg")

            # Build the error card
            email_body+=$(cat <<EOF

<div class="$card_class">
  <div class="error-header">
    <span>🔴 Error from IP: <strong>$ip</strong></span>
    <span class="severity-badge $badge_class">$severity</span>
  </div>

  <div style="margin: 10px 0;">
    <strong>Error Message:</strong><br>
    <code style="background: #f5f5f5; padding: 8px; display: block; border-radius: 3px; margin-top: 5px;">$sample_msg</code>
  </div>

  <div style="margin: 10px 0;">
    <strong>Occurrences:</strong> $count times in the last $TIME_WINDOW_HOURS hours
  </div>

  <div class="ip-intel">
    <strong>🔍 IP Intelligence:</strong><br>
    📍 Hostname: $hostname<br>
    🌐 ASN: $asn<br>
    🌍 Country: $country
  </div>

  <div class="recommendation">
    <strong>🤖 AI Recommendation:</strong><br>
    <div style="margin-top: 8px;">$recommendation</div>
  </div>

  <div class="decision-guide">
    $decision_guide
  </div>

  <div class="commands">
    <strong>⚡ ACTIONABLE COMMANDS (copy & paste):</strong><br><br>$commands
  </div>

  <div style="margin-top: 15px;">
    <strong>✅ Action Checklist:</strong>
    <ul class="checklist">
      <li>Review IP intelligence and determine if source is legitimate or malicious</li>
      <li>Run the suggested commands to investigate further</li>
      <li>Take appropriate action (whitelist, block, or configure)</li>
      <li>Monitor for recurring patterns from this IP</li>
    </ul>
  </div>
</div>
EOF
)
            debug_log "Added error card for IP $ip with severity $severity"
        fi
    done
    debug_log "Finished aggregated loop. Total API calls made: $api_call_count"
    echo "✓ CHECKPOINT: IP processing complete - $detailed_cards_added detailed cards added (threshold: $ERROR_THRESHOLD)" >&2

    # Warn if no cards were added
    if [ "$detailed_cards_added" -eq 0 ]; then
        echo "⚠ WARNING: No IPs exceeded threshold of $ERROR_THRESHOLD errors - email will contain executive summary only" >&2
    fi

    email_body+=$(cat <<'EOF'
<hr>
<h2>📋 Full Log Entries</h2>
<div class="full-logs">
  <p>Below are all error log entries captured in this report for reference:</p>
EOF
)
    # Append each full error log entry
    for err in "${errors[@]}"; do
        email_body+=$(cat <<EOF
<div class="log-entry">${err}</div>
EOF
)
    done
    email_body+=$(cat <<EOF
</div>

<div class="footer">
  <p>🛡️ This is an automated report from <strong>M.A.I.L. Sentinel</strong> (My Artificial Intelligence Log Sentinel)</p>
  <p>Report generated on <strong>$(hostname)</strong> at <strong>$(date '+%Y-%m-%d %H:%M:%S %Z')</strong></p>
  <p style="margin-top: 10px; color: #95a5a6;">Analyzed $((${#ip_errors_count[@]})) unique IP(s) | Total errors: ${#errors[@]} | Time window: $TIME_WINDOW_HOURS hours</p>
  <p style="margin-top: 10px;">Please do not reply directly to this automated message.</p>
</div>
</div>
</body>
</html>
EOF
)

    # Log that email is about to be sent
    debug_log "Sending aggregated email with $critical_count critical, $warning_count warning, $info_count info items"
    echo "✓ CHECKPOINT: Email body complete - sending to $email..." >&2
    {
        echo "Subject: 🛡️ M.A.I.L-Sentinel Report: $critical_count Critical, $warning_count Warning, $info_count Info - $(hostname)"
        echo "MIME-Version: 1.0"
        echo "Content-Type: text/html; charset=UTF-8"
        echo
        echo "$email_body"
    } | sendmail "$email"

    sendmail_exit=$?
    if [ $sendmail_exit -eq 0 ]; then
        debug_log "Aggregated email sent successfully"
        echo "✓ CHECKPOINT: Email sent successfully to $email" >&2
    else
        echo "✗ ERROR: sendmail failed with exit code $sendmail_exit" >&2
    fi
else
    if [ "$send_immediately" = false ]; then
        echo "ℹ INFO: No errors found in logs within the last $TIME_WINDOW_HOURS hours - no email sent" >&2
    fi
fi

echo "✓ CHECKPOINT: Script completed successfully at $(date '+%H:%M:%S')" >&2
exit 0
