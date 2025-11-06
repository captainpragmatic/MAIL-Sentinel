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
shopt -s inherit_errexit  # Bash 4.4+ - propagate errors from command substitution
shopt -s nullglob         # Empty glob expansions instead of literal strings

# Cleanup function called on exit
# shellcheck disable=SC2317,SC2329  # Called via trap
cleanup() {
    local exit_code=$?
    # Add any cleanup operations here if needed (temp files, etc.)
    # For now, just ensure we exit cleanly
    return "$exit_code"
}

# Error handler with better context
# shellcheck disable=SC2317,SC2329  # Called via trap
handle_error() {
    local exit_code=$?
    local line_no=$1
    echo "✗ FATAL: Error at line $line_no (exit code: $exit_code)" >&2
    echo "  Function: ${FUNCNAME[2]:-main}" >&2
    echo "  Command: $BASH_COMMAND" >&2
    exit "$exit_code"
}

# Setup traps
trap cleanup EXIT
trap 'handle_error $LINENO' ERR
trap 'echo "⚠ Script interrupted by user (SIGINT)" >&2; exit 130' INT
trap 'echo "⚠ Script terminated (SIGTERM)" >&2; exit 143' TERM

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

# List of log files to scan (procmail.log excluded - it's a delivery log, not an error log)
logfiles=( "/var/log/mail.log" "/var/log/mail.err" )

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

# Helper function for debug logging with timestamps
debug_log() {
    if [ "$MAIL_SENTINEL_DEBUG" = true ]; then
        echo "DEBUG [$(date '+%H:%M:%S')]: $*" >&2
    fi
}

# Build a plain-text automation summary for AI context
build_automation_summary() {
    local ip="$1"
    local hostname="$2"
    local error_count="$3"
    local sample_msg="$4"

    # Return empty if not an SSL/TLS error or automation is disabled
    if [ "${ENABLE_SSL_AUTOMATION:-true}" != "true" ] || ! grep -qiE "SSL_accept|TLS" <<< "$sample_msg" 2>/dev/null; then
        echo ""
        return
    fi

    local summary=""

    # Check 1: Known mail provider
    local is_known provider
    IFS='|' read -r is_known provider <<< "$(is_known_mail_provider "$hostname")"
    if [ "$is_known" = "true" ]; then
        summary+="Known provider: $provider. "
    else
        summary+="Unknown provider. "
    fi

    # Check 2: Certificate status
    if [ "${ENABLE_CERT_CHECK:-true}" = "true" ]; then
        local cert_status cert_date cert_days
        IFS='|' read -r cert_status cert_date cert_days <<< "$(check_ssl_certificate)"
        case "$cert_status" in
            expired) summary+="Cert: EXPIRED. " ;;
            expiring) summary+="Cert: Expiring in $cert_days days. " ;;
            valid) summary+="Cert: Valid ($cert_days days left). " ;;
            error) summary+="Cert: Unable to verify. " ;;
        esac
    fi

    # Check 3: Successful TLS connections
    if [ "${ENABLE_LOG_PATTERN_ANALYSIS:-true}" = "true" ]; then
        local tls_success_count
        tls_success_count=$(check_successful_tls_connections "$ip")
        tls_success_count=${tls_success_count:-0}
        if [ "$tls_success_count" -eq 0 ]; then
            summary+="No successful TLS connections from other IPs. "
        else
            summary+="$tls_success_count successful TLS connections from other IPs. "
        fi
    fi

    # Check 4: IP history
    local has_history history_count
    IFS='|' read -r has_history history_count <<< "$(check_ip_history "$ip")"
    if [ "$has_history" = "true" ]; then
        summary+="IP has $history_count successful delivery history. "
    else
        summary+="No delivery history. "
    fi

    # Check 5: Scanner confidence
    local scanner_confidence
    scanner_confidence=$(calculate_scanner_confidence "$ip" "$hostname" "$error_count" "$has_history")
    summary+="Scanner probability: $scanner_confidence%."

    echo "$summary"
}

# New function to call OpenAI API for recommendations with in-memory rate limiting and debug logging
get_fix_recommendation() {
    local error_summary="$1"
    local automation_context="${2:-}"  # Optional: automation telemetry summary
    debug_log "Entering get_fix_recommendation with summary: $error_summary"

    if ((__get_fix_recommendation_api_call_count >= API_CALL_LIMIT)); then
        debug_log "API call count limit reached: $__get_fix_recommendation_api_call_count"
        echo "Recommendation unavailable: API rate limit reached."
        return
    fi

    (( ++__get_fix_recommendation_api_call_count ))

    local prompt
    if [ -n "$automation_context" ]; then
        # Strategic prompt when automation data is available
        prompt="Postfix error: \"$error_summary\". Automation analysis: $automation_context. Provide strategic insights beyond the automated checks (e.g., security implications, long-term fixes, monitoring strategies). Max 100 words."
    else
        # Standard prompt for non-automated errors
        prompt="Summarize the following Postfix error in a concise bullet-point list with three recommendations on how to fix, prevent, or ignore it (max 100 words): \"$error_summary\"."
    fi

    # Build a safe JSON payload using jq
    local payload
    local model="${OPENAI_MODEL:-gpt-5-mini}"

    # Newer models (gpt-5, gpt-4.1 series, o-series) use max_completion_tokens instead of max_tokens
    if [[ "$model" =~ ^(gpt-5|gpt-4\.1|o[0-9]|o[0-9]-) ]]; then
        payload=$(jq -n --arg model "$model" --arg prompt "$prompt" '{
                            model: $model,
                            messages: [{role: "user", content: $prompt}],
                            max_completion_tokens: 100,
                            temperature: 0.4
                        }')
    else
        payload=$(jq -n --arg model "$model" --arg prompt "$prompt" '{
                            model: $model,
                            messages: [{role: "user", content: $prompt}],
                            max_tokens: 100,
                            temperature: 0.4
                        }')
    fi

    # Call OpenAI API with a maximum time configured via MAX_API_TIMEOUT
    local response
    response=$(curl --max-time "$MAX_API_TIMEOUT" -s https://api.openai.com/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $OPENAI_API_KEY" \
        -d "$payload" 2>/dev/null)

    local curl_exit_code=$?
    if [ "$curl_exit_code" -ne 0 ] || [ -z "$response" ]; then
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

    if [ "$ip" = "unknown" ] || [ "$ip" = "internal" ] || [ -z "$ip" ]; then
        echo "unknown|unknown|unknown"
        return 0
    fi

    # Validate IP format
    if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        debug_log "Invalid IP format for intelligence lookup: $ip"
        echo "unknown|unknown|unknown"
        return 0
    fi

    # Try to get hostname with timeout
    set +e  # Disable exit on error temporarily
    local host_output
    if host_output=$(timeout 3 host "$ip" 2>/dev/null); then
        hostname=$(grep "domain name pointer" <<< "$host_output" | awk '{print $NF}' | sed 's/\.$//' 2>/dev/null || echo "unknown")
    fi
    set -e

    # Try to get ASN and country info from whois with timeout
    set +e
    local whois_output
    whois_output=$(timeout 5 whois "$ip" 2>/dev/null)
    local whois_exit=$?
    set -e

    if [ "$whois_exit" -eq 0 ] && [ -n "$whois_output" ]; then
        asn=$(grep -iE "^(origin|originas):" <<< "$whois_output" 2>/dev/null | head -1 | awk '{print $NF}' || echo "unknown")
        country=$(grep -i "^country:" <<< "$whois_output" 2>/dev/null | head -1 | awk '{print $NF}' || echo "unknown")
    elif [ "$whois_exit" -eq 124 ]; then
        debug_log "whois timeout for IP: $ip"
    fi

    echo "${hostname:-unknown}|${asn:-unknown}|${country:-unknown}"
    return 0
}

# Categorize error severity
categorize_severity() {
    local ip="$1"
    local error_line="$2"
    local count="$3"

    # Truncate message for logging (first 80 chars)
    local msg_preview="${error_line:0:80}"
    [ ${#error_line} -gt 80 ] && msg_preview="${msg_preview}..."

    debug_log "categorize_severity: IP=$ip, count=$count, msg='$msg_preview'"

    # Input validation
    if [ -z "$error_line" ]; then
        debug_log "IP=$ip: empty error_line provided -> severity=INFO"
        echo "INFO"
        return 0
    fi

    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        debug_log "IP=$ip: invalid count value: $count - defaulting to 0"
        count=0
    fi

    # Check if it matches known safe patterns (INFO level)
    # Using grep with here-string (safer than pipe) and timeout
    if timeout 2 grep -qE "$KNOWN_SAFE_PATTERNS" <<< "$error_line" 2>/dev/null; then
        local matched_pattern
        matched_pattern=$(grep -oE "$KNOWN_SAFE_PATTERNS" <<< "$error_line" 2>/dev/null | head -1)
        debug_log "IP=$ip matched KNOWN_SAFE_PATTERNS '$matched_pattern' -> severity=INFO"
        echo "INFO"
        return 0
    fi

    # Critical: authentication failures, service disruptions, delivery failures
    if timeout 2 grep -qiE "authentication failed|service unavailable|queue file write error|disk full|fatal" <<< "$error_line" 2>/dev/null; then
        local matched_pattern
        matched_pattern=$(grep -oiE "authentication failed|service unavailable|queue file write error|disk full|fatal" <<< "$error_line" 2>/dev/null | head -1)
        debug_log "IP=$ip matched CRITICAL pattern '$matched_pattern' -> severity=CRITICAL"
        echo "CRITICAL"
        return 0
    fi

    # Warning: SSL errors, connection issues, bounces, deferred
    if timeout 2 grep -qiE "SSL_accept|TLS|connection reset|bounced|deferred|timeout" <<< "$error_line" 2>/dev/null; then
        local matched_pattern
        matched_pattern=$(grep -oiE "SSL_accept|TLS|connection reset|bounced|deferred|timeout" <<< "$error_line" 2>/dev/null | head -1)
        if [ "$count" -gt 10 ]; then
            debug_log "IP=$ip matched pattern '$matched_pattern' (count=$count>10) -> severity=WARNING"
            echo "WARNING"
        else
            debug_log "IP=$ip matched pattern '$matched_pattern' (count=$count<=10) -> severity=INFO"
            echo "INFO"
        fi
        return 0
    fi

    # Default to INFO for low-count errors
    if [ "$count" -le "$AUTO_IGNORE_THRESHOLD" ]; then
        debug_log "IP=$ip no patterns matched, count=$count<=$AUTO_IGNORE_THRESHOLD -> severity=INFO (default)"
        echo "INFO"
    else
        debug_log "IP=$ip no patterns matched, count=$count>$AUTO_IGNORE_THRESHOLD -> severity=WARNING (default)"
        echo "WARNING"
    fi
    return 0
}

# Detect available fail2ban jails for mail services
get_fail2ban_jails() {
    local jails=""

    # Check if fail2ban-client is available
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "none"
        return
    fi

    # Get list of active jails
    set +e
    local status_output
    status_output=$(fail2ban-client status 2>/dev/null)
    local exit_code=$?
    set -e

    if [ "$exit_code" -ne 0 ] || [ -z "$status_output" ]; then
        echo "none"
        return
    fi

    # Extract jail names and filter for mail-related ones
    local all_jails
    all_jails=$(echo "$status_output" | grep "Jail list:" | sed 's/.*Jail list:[[:space:]]*//' | tr ',' '\n' | tr -d ' ')

    # Filter for mail-related jails (postfix, dovecot, sasl, etc.)
    for jail in $all_jails; do
        if [[ "$jail" =~ ^(postfix|dovecot|sasl|mail) ]]; then
            jails="$jails $jail"
        fi
    done

    if [ -z "$jails" ]; then
        echo "none"
    else
        echo "$jails" | xargs
    fi
}

# Generate specific command suggestions based on error type
get_command_suggestions() {
    local error_line="$1"
    local ip="$2"
    local commands=""

    # SSL/TLS errors: no manual commands needed - automation handles all checks
    # (certificate validity, expiry, successful connections, scanner detection)

    if grep -qiE "connection reset|refused|timeout" <<< "$error_line" 2>/dev/null; then
        commands+="# Check if IP is on blocklists:\n"
        commands+="# Visit: https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a$ip\n\n"

        # Auto-detect fail2ban jails and provide specific commands
        local jails
        jails=$(get_fail2ban_jails)

        if [ "$jails" != "none" ]; then
            commands+="# Block this IP with fail2ban:\n"
            for jail in $jails; do
                commands+="fail2ban-client set $jail banip $ip\n"
            done
            commands+="\n"
        else
            commands+="# fail2ban not available or no mail jails configured\n\n"
        fi

        commands+="# Or block with iptables:\n"
        commands+="iptables -A INPUT -s $ip -j DROP\n\n"
    fi

    if grep -qiE "authentication failed" <<< "$error_line" 2>/dev/null; then
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

    if grep -qiE "SSL_accept|TLS" <<< "$error_line" 2>/dev/null; then
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
    elif grep -qiE "connection reset|refused" <<< "$error_line" 2>/dev/null; then
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

# ============================================================================
# SMART AUTOMATION FUNCTIONS
# ============================================================================

# Check if hostname belongs to a known mail provider
is_known_mail_provider() {
    local hostname="$1"

    if [ "$hostname" = "unknown" ] || [ -z "$hostname" ]; then
        echo "false|unknown"
        return
    fi

    # Use KNOWN_MAIL_PROVIDERS from config, fallback to defaults
    local providers="${KNOWN_MAIL_PROVIDERS:-google\\.com|outlook\\.com|yahoodns\\.net|icloud\\.com|amazonses\\.com|sendgrid\\.net|mailgun}"

    if grep -qiE "$providers" <<< "$hostname" 2>/dev/null; then
        local provider
        provider=$(grep -oiE "$providers" <<< "$hostname" 2>/dev/null | head -1)
        echo "true|$provider"
    else
        echo "false|unknown"
    fi
}

# Check SSL certificate validity on local mail server
check_ssl_certificate() {
    # Returns: "valid|date|days" or "expired|date" or "expiring|date|days" or "error|message"

    local cert_info
    local hostname_fqdn
    hostname_fqdn=$(hostname 2>/dev/null)

    # Use timeout and suppress errors
    set +e
    cert_info=$(echo | timeout 5 openssl s_client -connect "${hostname_fqdn}:25" -starttls smtp 2>/dev/null | \
                openssl x509 -noout -enddate 2>/dev/null)
    local exit_code=$?
    set -e

    if [ "$exit_code" -ne 0 ] || [ -z "$cert_info" ]; then
        echo "error|Unable to check certificate"
        return
    fi

    local expiry_date
    expiry_date=$(echo "$cert_info" | grep -oP 'notAfter=\K.*' 2>/dev/null)

    if [ -z "$expiry_date" ]; then
        echo "error|Unable to parse certificate date"
        return
    fi

    local expiry_epoch current_epoch
    set +e
    expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null)
    local date_exit=$?
    set -e
    current_epoch=$(date +%s)

    if [ "$date_exit" -ne 0 ]; then
        echo "error|Unable to parse date"
        return
    fi

    if [ "$expiry_epoch" -lt "$current_epoch" ]; then
        echo "expired|$expiry_date"
    else
        local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
        local warn_days="${CERT_EXPIRY_WARNING_DAYS:-30}"
        if [ "$days_left" -lt "$warn_days" ]; then
            echo "expiring|$expiry_date|$days_left"
        else
            echo "valid|$expiry_date|$days_left"
        fi
    fi
}

# Check for successful TLS connections from other IPs
check_successful_tls_connections() {
    local exclude_ip="$1"

    local success_count=0
    local recent_logs="/var/log/mail.log"

    # Look for successful STARTTLS patterns in Postfix logs
    # Pattern: "disconnect from ... starttls=1" means TLS succeeded
    # Pattern: "disconnect from ... starttls=0/1" means TLS failed (exclude this)
    if [ -f "$recent_logs" ]; then
        set +e
        # Count successful STARTTLS (starttls=1, but NOT starttls=0/1)
        success_count=$(grep "postfix/smtpd" "$recent_logs" 2>/dev/null | \
                       grep "starttls=1" | \
                       grep -v "starttls=0/1" | \
                       grep -v "$exclude_ip" | \
                       tail -100 | \
                       wc -l)
        set -e
        # Sanitize output - ensure it's a clean integer
        success_count=$(echo "$success_count" | tr -d ' \n\r' | grep -oE '^[0-9]+$' || echo 0)
    fi

    echo "$success_count"
}

# Check if IP has successful delivery history
check_ip_history() {
    local ip="$1"

    local success_count=0

    # Check recent and archived logs
    for logfile in /var/log/mail.log /var/log/mail.log.1; do
        [ -f "$logfile" ] || continue
        set +e
        local count
        count=$(grep "$ip" "$logfile" 2>/dev/null | grep -cE "status=sent|delivered" 2>/dev/null)
        # Ensure count is a valid integer, default to 0
        count=${count:-0}
        count=$(echo "$count" | tr -d '\n\r' | grep -oE '^[0-9]+$' || echo 0)
        success_count=$(( success_count + count ))
        set -e
        [ "$success_count" -gt 0 ] && break
    done

    if [ "$success_count" -gt 0 ]; then
        echo "true|$success_count"
    else
        echo "false|0"
    fi
}

# Calculate scanner confidence score (0.0-1.0)
calculate_scanner_confidence() {
    local ip="$1"
    local hostname="$2"
    local error_count="$3"
    local has_successful_history="$4"

    local confidence=0

    # High error count (>10 in time window): +30 points
    [ "$error_count" -gt 10 ] && confidence=$(( confidence + 30 ))

    # No rDNS or generic hostname: +25 points
    if [ "$hostname" = "unknown" ] || \
       grep -qiE "static|dynamic|pool|broadband|cable|dsl|dial" <<< "$hostname" 2>/dev/null; then
        confidence=$(( confidence + 25 ))
    fi

    # No successful history: +25 points
    [ "$has_successful_history" = "false" ] && confidence=$(( confidence + 25 ))

    # Very high error count (>50): +20 points
    [ "$error_count" -gt 50 ] && confidence=$(( confidence + 20 ))

    # Return as percentage (0-100)
    echo "$confidence"
}

# Main automated SSL/TLS analysis function
get_automated_ssl_analysis() {
    local ip="$1"
    local hostname="$2"
    local error_count="$3"
    local sample_msg="$4"

    local output=""
    output+="<strong>🤖 AUTOMATED SSL/TLS ANALYSIS:</strong><br>"
    output+="<div style='margin: 10px 0; padding: 10px; background: #f0f8ff; border-left: 4px solid #2196F3;'>"

    # Check 1: Known mail provider detection
    local is_known provider
    IFS='|' read -r is_known provider <<< "$(is_known_mail_provider "$hostname")"

    output+="<div style='margin: 8px 0;'>"
    if [ "$is_known" = "true" ]; then
        output+="✅ <strong>Check 1:</strong> IP from known mail provider: <code>$provider</code><br>"
        output+="<span style='color: #d32f2f; font-weight: bold;'>⚠️ CRITICAL: Your SSL certificate may be expired or misconfigured!</span><br>"
        output+="<span style='font-size: 0.9em;'>Legitimate mail providers should connect successfully. Check cert validity immediately.</span>"
    else
        output+="✅ <strong>Check 1:</strong> Not from known provider → Proceeding to next checks"
    fi
    output+="</div>"

    # Check 2: SSL certificate validity
    if [ "${ENABLE_CERT_CHECK:-true}" = "true" ]; then
        local cert_status cert_date cert_days
        IFS='|' read -r cert_status cert_date cert_days <<< "$(check_ssl_certificate)"

        output+="<div style='margin: 8px 0;'>"
        output+="✅ <strong>Check 2:</strong> SSL Certificate Status: "

        case "$cert_status" in
            expired)
                output+="<span style='color: #d32f2f; font-weight: bold;'>EXPIRED</span> (expired on: $cert_date)<br>"
                output+="<span style='font-size: 0.9em;'>🔴 ACTION REQUIRED: Renew certificate immediately!</span>"
                ;;
            expiring)
                output+="<span style='color: #f57c00; font-weight: bold;'>EXPIRING SOON</span> (expires in $cert_days days)<br>"
                output+="<span style='font-size: 0.9em;'>🟡 WARNING: Renew certificate within $cert_days days</span>"
                ;;
            valid)
                output+="<span style='color: #388e3c; font-weight: bold;'>VALID</span> (expires: $cert_date, $cert_days days remaining)"
                ;;
            error)
                output+="<span style='color: #757575;'>Unable to verify ($cert_date)</span>"
                ;;
        esac
        output+="</div>"
    fi

    # Check 3: Successful TLS from other IPs
    local tls_success_count=0
    if [ "${ENABLE_LOG_PATTERN_ANALYSIS:-true}" = "true" ]; then
        tls_success_count=$(check_successful_tls_connections "$ip")
        # Ensure it's a valid integer
        tls_success_count=${tls_success_count:-0}

        output+="<div style='margin: 8px 0;'>"
        output+="✅ <strong>Check 3:</strong> Recent successful TLS connections: $tls_success_count<br>"

        if [ "$tls_success_count" -eq 0 ]; then
            output+="<span style='color: #d32f2f; font-weight: bold;'>🔴 CRITICAL: No successful TLS connections found!</span><br>"
            output+="<span style='font-size: 0.9em;'>This suggests a global SSL/TLS configuration problem.</span>"
        else
            output+="<span style='color: #388e3c;'>✓ SSL/TLS working for other IPs → This IP likely has client-side issues or is a scanner</span>"
        fi
        output+="</div>"
    fi

    # Check 4: IP history
    local has_history history_count
    IFS='|' read -r has_history history_count <<< "$(check_ip_history "$ip")"

    output+="<div style='margin: 8px 0;'>"
    output+="✅ <strong>Check 4:</strong> Historical delivery success: "
    if [ "$has_history" = "true" ]; then
        output+="<span style='color: #388e3c;'>YES ($history_count deliveries)</span><br>"
        output+="<span style='font-size: 0.9em;'>This IP has successfully delivered mail before. Recent SSL errors may indicate a new issue.</span>"
    else
        output+="<span style='color: #f57c00;'>NO</span><br>"
        output+="<span style='font-size: 0.9em;'>First contact or never successful → May be scanner or misconfigured client</span>"
    fi
    output+="</div>"

    # Check 5: Scanner confidence score
    local scanner_confidence
    scanner_confidence=$(calculate_scanner_confidence "$ip" "$hostname" "$error_count" "$has_history")

    output+="<div style='margin: 8px 0;'>"
    output+="✅ <strong>Check 5:</strong> Scanner probability: "

    if [ "$scanner_confidence" -ge 70 ]; then
        output+="<span style='color: #d32f2f; font-weight: bold;'>HIGH ($scanner_confidence%)</span><br>"
        output+="<span style='font-size: 0.9em;'>🔴 Likely a scanner. Safe to block.</span>"
    elif [ "$scanner_confidence" -ge 40 ]; then
        output+="<span style='color: #f57c00; font-weight: bold;'>MEDIUM ($scanner_confidence%)</span><br>"
        output+="<span style='font-size: 0.9em;'>🟡 Possible scanner. Monitor before blocking.</span>"
    else
        output+="<span style='color: #388e3c;'>LOW ($scanner_confidence%)</span><br>"
        output+="<span style='font-size: 0.9em;'>✓ May be legitimate. Investigate further.</span>"
    fi
    output+="</div>"

    # Final recommendation
    output+="<div style='margin-top: 15px; padding: 10px; background: #fff3e0; border-left: 4px solid #ff9800;'>"
    output+="<strong>📋 AUTOMATED RECOMMENDATION:</strong><br>"

    # Decision logic
    if [ "$is_known" = "true" ] && [ "$cert_status" = "expired" ]; then
        output+="<strong style='color: #d32f2f;'>URGENT ACTION REQUIRED:</strong> Certificate expired. Renew immediately to restore mail flow from major providers."
    elif [ "$tls_success_count" -eq 0 ]; then
        output+="<strong style='color: #d32f2f;'>URGENT:</strong> Global SSL/TLS failure detected. Fix server configuration immediately."
    elif [ "$scanner_confidence" -ge 70 ]; then
        output+="<strong style='color: #f57c00;'>RECOMMENDED:</strong> Block this IP (high scanner probability)."
    elif [ "$has_history" = "true" ]; then
        output+="<strong style='color: #2196F3;'>INVESTIGATE:</strong> IP has successful history but now failing. Check for client-side changes."
    else
        output+="<strong style='color: #388e3c;'>MONITOR:</strong> Low risk. No immediate action required."
    fi

    output+="</div>"
    output+="</div>"

    echo "$output"
}

# Process each logfile in the defined logfiles list
for logfile in "${logfiles[@]}"; do
    [[ -f "$logfile" ]] || continue
    # Replace the while read loop with a mapfile loop to avoid subshell side effects:
    mapfile -t lines < <(tac "$logfile")
    for line in "${lines[@]}"; do
        # Skip empty lines and continuation lines (starting with whitespace)
        [[ -z "$line" || "$line" =~ ^[[:space:]] ]] && continue

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
            debug_log "Failed to convert timestamp from line: $line"
            continue
        fi
        if [ "$log_epoch" -lt "$cutoff_epoch" ]; then
            break
        fi

        # Skip lines matching the ignored patterns (using here-string instead of pipe)
        if grep -Ei "$ignored_pattern" <<< "$line" >/dev/null 2>&1; then
            continue
        fi

        # Check if the line contains flagged patterns (using here-string instead of pipe)
        if grep -Ei "$pattern" <<< "$line" >/dev/null 2>&1; then
            # Extract remote IP using primary regex (assuming it is preceded by "rip=")
            ip=$(grep -oP 'rip=\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' <<< "$line" 2>/dev/null || true)
            if [ -z "$ip" ]; then
                # Fallback: extract the first valid IPv4 address found in the line
                candidate=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$line" 2>/dev/null | head -n 1 || true)
                if [ -n "$candidate" ]; then
                    ip="$candidate"
                else
                    # No IP found - mark as internal error
                    ip="internal"
                    debug_log "Marking error as internal (no IP): ${line:0:100}"
                fi
            fi

            # Skip localhost/internal connections
            if [ "$ip" = "127.0.0.1" ] || [ "$ip" = "::1" ]; then
                debug_log "Skipping localhost connection: ${line:0:100}"
                continue
            fi

            # Remove the timestamp for a uniform summary message
            sample_msg=$(echo "$line" | cut -d' ' -f2-)

            # Group errors by IP: count occurrences and keep one sample message per IP
            ip_errors_count["$ip"]=$(( ${ip_errors_count["$ip"]:-0} + 1 ))
            if [ "${ip_errors_count["$ip"]:-0}" -eq 1 ]; then
                ip_errors_sample["$ip"]="$sample_msg"
                # Categorize severity for this IP (will be updated later based on final count)
                severity=$(categorize_severity "$ip" "$sample_msg" "${ip_errors_count["$ip"]:-1}")
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

    # Validate arrays before processing
    if [ ${#ip_errors_count[@]} -eq 0 ]; then
        echo "⚠ WARNING: ip_errors_count array is empty despite having errors - this is unexpected" >&2
        echo "ℹ INFO: Skipping email generation" >&2
        exit 0
    fi

    if [ ${#ip_errors_count[@]} -ne ${#ip_errors_sample[@]} ]; then
        echo "⚠ WARNING: Array size mismatch detected!" >&2
        echo "  ip_errors_count: ${#ip_errors_count[@]} entries" >&2
        echo "  ip_errors_sample: ${#ip_errors_sample[@]} entries" >&2
        echo "  Continuing with caution..." >&2
    fi

    # Recategorize severity based on final counts and count by severity
    echo "✓ CHECKPOINT: About to start loop over ${#ip_errors_count[@]} IPs..." >&2
    ip_counter=0
    echo "✓ CHECKPOINT: ip_counter initialized, entering loop..." >&2
    for ip in "${!ip_errors_count[@]}"; do
        ((++ip_counter))
        echo "  → [$(date '+%H:%M:%S')] Processing IP $ip_counter/${#ip_errors_count[@]}: $ip" >&2

        # Validate IP format (IPv4 or "internal")
        if ! [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|^internal$ ]]; then
            echo "    ⚠ WARNING: Invalid IP format detected: '$ip' - skipping" >&2
            continue
        fi

        # Check if this IP has a sample message
        if [ -z "${ip_errors_sample[$ip]+isset}" ]; then
            echo "    ⚠ WARNING: IP $ip missing from sample array - skipping" >&2
            continue
        fi

        count=${ip_errors_count[$ip]:-0}
        sample_msg=${ip_errors_sample[$ip]:-"No sample message"}

        echo "    Count: $count, calling categorize_severity..." >&2
        # Call categorize_severity with error protection
        # Note: timeout within the function (grep calls) provides timeout protection
        set +e  # Temporarily disable exit on error for this block
        severity=$(categorize_severity "$ip" "$sample_msg" "$count")
        cat_exit_code=$?
        set -e  # Re-enable exit on error

        if [ "$cat_exit_code" -eq 0 ]; then
            echo "    Severity: $severity" >&2
        else
            echo "    ✗ ERROR: categorize_severity failed (exit code: $cat_exit_code) for IP $ip" >&2
            severity="INFO"
            echo "    Severity: $severity (fallback)" >&2
        fi

        # Validate severity value
        if ! [[ "$severity" =~ ^(CRITICAL|WARNING|INFO)$ ]]; then
            echo "    ⚠ WARNING: Invalid severity '$severity' for IP $ip - defaulting to INFO" >&2
            severity="INFO"
        fi

        ip_errors_severity["$ip"]="$severity"

        case "$severity" in
            CRITICAL) (( ++critical_count )) ;;
            WARNING) (( ++warning_count )) ;;
            INFO) (( ++info_count )) ;;
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
  <h1>M.A.I.L-Sentinel Report</h1>
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
        severity=${ip_errors_severity[$ip]:-INFO}
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
        count=${ip_errors_count[$ip]:-0}
        sample_msg=${ip_errors_sample[$ip]:-"No sample message"}
        severity=${ip_errors_severity[$ip]:-INFO}

        # Only include errors at or above the threshold
        if [ "$count" -ge "$ERROR_THRESHOLD" ]; then
            (( ++detailed_cards_added ))
            summary_line="$ip: $sample_msg (occurred $count times)"

            # Determine card CSS class based on severity
            case "$severity" in
                CRITICAL) card_class="error-card" badge_class="badge-critical" ;;
                WARNING) card_class="error-card warning" badge_class="badge-warning" ;;
                INFO) card_class="error-card info" badge_class="badge-info" ;;
                *) card_class="error-card" badge_class="badge-warning" ;;
            esac

            # Handle internal errors differently (no IP intelligence, AI, or automation)
            if [ "$ip" = "internal" ]; then
                # Internal server errors - simplified card
                hostname=""
                asn=""
                country=""
                recommendation=""

                # Build improved commands with proper formatting
                commands="# Review server configuration:
journalctl -u postfix -n 100

# Check TLS configuration:
postconf | grep tls

# Review mail queue:
mailq

# Check disk space:
df -h /var/spool/postfix"

                # Build severity-aware guidance
                action_needed="⚠️ <strong>ACTION RECOMMENDED</strong>"
                if [ "$severity" = "CRITICAL" ] || [ "$count" -gt 20 ]; then
                    action_needed="🔴 <strong>URGENT ACTION REQUIRED</strong>"
                elif [ "$count" -le 5 ]; then
                    action_needed="ℹ️ <strong>INFORMATIONAL - Monitor</strong>"
                fi

                decision_guide="<strong>📌 INTERNAL ERROR GUIDANCE:</strong>
<div style='margin: 10px 0; padding: 10px; background: #fff3e0; border-left: 4px solid #ff9800;'>
$action_needed<br><br>
This error originates from the mail server itself, not from a remote connection.
<ul style='margin: 10px 0; padding-left: 20px;'>
<li><strong>Error Count:</strong> $count occurrence(s) - $([ "$count" -gt 20 ] && echo "High frequency suggests systemic issue" || [ "$count" -gt 10 ] && echo "Moderate frequency" || echo "Low frequency")</li>
<li><strong>Severity:</strong> $severity</li>
<li><strong>Likely Causes:</strong> Disk space issues, SSL/TLS certificate problems, configuration errors, or service availability</li>
<li><strong>Next Steps:</strong> Review server logs, check disk space, verify TLS certificates, and ensure Postfix service is running properly</li>
</ul>
</div>"
            else
                # Regular IP-based errors - full analysis
                # Get IP intelligence
                if [ -n "${ip_intelligence_cache[$ip]+isset}" ]; then
                    ip_intel="${ip_intelligence_cache[$ip]}"
                else
                    ip_intel=$(get_ip_intelligence "$ip")
                    ip_intelligence_cache["$ip"]="$ip_intel"
                fi
                IFS='|' read -r hostname asn country <<< "$ip_intel"

                # Build automation context summary for AI (if applicable)
                automation_summary=$(build_automation_summary "$ip" "$hostname" "$count" "$sample_msg")

                # Get AI recommendation if within limit
                if [ "$api_call_count" -lt "$API_CALL_LIMIT" ]; then
                    debug_log "Making API call for: $summary_line"
                    recommendation=$(get_fix_recommendation "$summary_line" "$automation_summary")
                    (( ++api_call_count ))
                    debug_log "api_call_count is now: $api_call_count"
                else
                    recommendation="⚠️ Recommendation unavailable: API rate limit reached ($API_CALL_LIMIT max per report)."
                fi

                # Get command suggestions and decision guide
                commands=$(get_command_suggestions "$sample_msg" "$ip")

                # Use automated analysis for SSL/TLS errors if enabled, otherwise use static guide
                if [ "${ENABLE_SSL_AUTOMATION:-true}" = "true" ] && grep -qiE "SSL_accept|TLS" <<< "$sample_msg" 2>/dev/null; then
                    debug_log "Using automated SSL/TLS analysis for $ip"
                    decision_guide=$(get_automated_ssl_analysis "$ip" "$hostname" "$count" "$sample_msg")
                else
                    decision_guide=$(get_decision_guide "$sample_msg")
                fi
            fi

            # Build the error card
            if [ "$ip" = "internal" ]; then
                header_text="⚙️ Internal Server Error"
            else
                header_text="🔴 Error from IP: <strong>$ip</strong>"
            fi

            # Build the card with conditional sections
            email_body+="
<div class=\"$card_class\">
  <div class=\"error-header\">
    <span>$header_text</span>
    <span class=\"severity-badge $badge_class\">$severity</span>
  </div>

  <div style=\"margin: 10px 0;\">
    <strong>Error Message:</strong><br>
    <code style=\"background: #f5f5f5; padding: 8px; display: block; border-radius: 3px; margin-top: 5px;\">$sample_msg</code>
  </div>

  <div style=\"margin: 10px 0;\">
    <strong>Occurrences:</strong> $count times in the last $TIME_WINDOW_HOURS hours
  </div>
"

            # Only show IP Intelligence section if hostname is not empty
            if [ -n "$hostname" ]; then
                email_body+="
  <div class=\"ip-intel\">
    <strong>🔍 IP Intelligence:</strong><br>
    📍 Hostname: $hostname<br>
    🌐 ASN: $asn<br>
    🌍 Country: $country
  </div>
"
            fi

            # Only show AI Recommendation section if recommendation is not empty
            if [ -n "$recommendation" ]; then
                email_body+="
  <div class=\"recommendation\">
    <strong>🤖 AI Recommendation:</strong><br>
    <div style=\"margin-top: 8px;\">$recommendation</div>
  </div>
"
            fi

            email_body+="
  <div class=\"decision-guide\">
    $decision_guide
  </div>

  <div class=\"commands\">
    <strong>⚡ ACTIONABLE COMMANDS (copy & paste):</strong><br><br>$commands
  </div>
</div>
"
            debug_log "Added error card for IP $ip with severity $severity"
        fi
    done
    debug_log "Finished aggregated loop. Total API calls made: $api_call_count"
    echo "✓ CHECKPOINT: IP processing complete - $detailed_cards_added detailed cards added (threshold: $ERROR_THRESHOLD)" >&2

    # Warn if no cards were added
    if [ "$detailed_cards_added" -eq 0 ]; then
        echo "⚠ WARNING: No IPs exceeded threshold of $ERROR_THRESHOLD errors - email will contain executive summary only" >&2
    fi

    # Add Low Priority section for IPs below ERROR_THRESHOLD
    low_priority_count=0
    for ip in "${critical_ips[@]}" "${warning_ips[@]}" "${info_ips[@]}"; do
        [ -z "$ip" ] && continue
        count=${ip_errors_count[$ip]:-0}
        if [ "$count" -lt "$ERROR_THRESHOLD" ] && [ "$count" -gt 0 ]; then
            (( ++low_priority_count ))
        fi
    done

    if [ "$low_priority_count" -gt 0 ]; then
        email_body+=$(cat <<EOF

<hr>
<h2>📊 Low Priority Errors</h2>
<div style="background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #6c757d;">
  <p><strong>$low_priority_count IP(s)</strong> with fewer than $ERROR_THRESHOLD errors (below detailed analysis threshold).</p>
  <details>
    <summary style="cursor: pointer; color: #007bff; font-weight: bold;">Click to expand low priority errors</summary>
    <table style="width: 100%; margin-top: 15px; border-collapse: collapse;">
      <thead>
        <tr style="background: #e9ecef;">
          <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">IP Address</th>
          <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Count</th>
          <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Severity</th>
          <th style="padding: 8px; text-align: left; border: 1px solid #dee2e6;">Sample Message</th>
        </tr>
      </thead>
      <tbody>
EOF
)

        # Add low priority IPs to table
        for ip in "${critical_ips[@]}" "${warning_ips[@]}" "${info_ips[@]}"; do
            [ -z "$ip" ] && continue
            count=${ip_errors_count[$ip]:-0}

            if [ "$count" -lt "$ERROR_THRESHOLD" ] && [ "$count" -gt 0 ]; then
                sample_msg=${ip_errors_sample[$ip]:-"No sample message"}
                severity=${ip_errors_severity[$ip]:-INFO}

                # Truncate message for table display
                display_msg="${sample_msg:0:100}"
                [ ${#sample_msg} -gt 100 ] && display_msg="${display_msg}..."

                # Choose row color based on severity
                case "$severity" in
                    CRITICAL) row_color="#fee" ;;
                    WARNING) row_color="#ffe" ;;
                    INFO) row_color="#eff" ;;
                    *) row_color="#fff" ;;
                esac

                email_body+=$(cat <<EOF
        <tr style="background: $row_color;">
          <td style="padding: 8px; border: 1px solid #dee2e6;"><code>$ip</code></td>
          <td style="padding: 8px; border: 1px solid #dee2e6;">$count</td>
          <td style="padding: 8px; border: 1px solid #dee2e6;"><span style="font-weight: bold; color: $([ "$severity" = "CRITICAL" ] && echo "#d32f2f" || [ "$severity" = "WARNING" ] && echo "#f57c00" || echo "#2196F3");">$severity</span></td>
          <td style="padding: 8px; border: 1px solid #dee2e6; font-family: monospace; font-size: 0.9em;">$display_msg</td>
        </tr>
EOF
)
            fi
        done

        email_body+=$(cat <<'EOF'
      </tbody>
    </table>
  </details>
</div>
EOF
)
        echo "✓ CHECKPOINT: Added low priority section with $low_priority_count IPs" >&2
    fi

    email_body+=$(cat <<EOF

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

    # Set default values for From header if not configured
    from_name="${MAIL_FROM_NAME:-M.A.I.L. Sentinel}"
    from_email="${MAIL_FROM_EMAIL:-sentinel@$(hostname)}"

    {
        echo "From: $from_name <$from_email>"
        echo "Subject: 🛡️ M.A.I.L-Sentinel Report: $critical_count Critical, $warning_count Warning, $info_count Info - $(hostname)"
        echo "MIME-Version: 1.0"
        echo "Content-Type: text/html; charset=UTF-8"
        echo
        echo "$email_body"
    } | sendmail "$email"

    sendmail_exit=$?
    if [ "$sendmail_exit" -eq 0 ]; then
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
