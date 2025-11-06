#!/bin/bash
# M.A.I.L. Sentinel - Installation Script
# This script helps you set up M.A.I.L. Sentinel on your system

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ASCII Art Banner
echo -e "${CYAN}"
cat << "EOF"
 __  __   _   ___ _    
|  \/  | /_\ |_ _| |   
| |\/| |/ _ \ | || |__ 
|_|  |_/_/ \_\___|____|
                       
 ___ ___ _  _ _____ ___ _  _ ___ _    
/ __| __| \| |_   _|_ _| \| | __| |   
\__ \ _|| .` | | |  | || .` | _|| |__ 
|___/___|_|\_| |_| |___|_|\_|___|____|

My Artificial Intelligence Log Sentinel
EOF
echo -e "${NC}"

echo -e "${BOLD}Welcome to the M.A.I.L. Sentinel installation!${NC}\n"
echo -e "This script will help you set up M.A.I.L. Sentinel on your system.\n"

# Function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}❌ Required command '$1' is not installed.${NC}"
        echo -e "Please install it using your package manager and run this script again."
        echo -e "For example: ${YELLOW}sudo apt-get install $1${NC} or ${YELLOW}sudo yum install $1${NC}"
        return 1
    else
        echo -e "${GREEN}✅ Found $1${NC}"
        return 0
    fi
}

# Check for dependencies
echo -e "\n${BOLD}Checking dependencies...${NC}"
dependencies=("jq" "curl" "tac" "mail" "sendmail" "awk" "sed" "host" "whois" "timeout")
missing_deps=false

for dep in "${dependencies[@]}"; do
    if ! check_command "$dep"; then
        missing_deps=true
    fi
done

if [ "$missing_deps" = true ]; then
    echo -e "\n${RED}Please install the missing dependencies and run the script again.${NC}"
    exit 1
fi

echo -e "\n${GREEN}All dependencies are satisfied! ✨${NC}\n"

# Create the config directory if it doesn't exist
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.sh"

# Configuration setup
echo -e "${BOLD}Let's configure M.A.I.L. Sentinel:${NC}"

# Email configuration
echo -e "\n${BLUE}📧 Email Configuration${NC}"
read -r -p "Enter the email address to receive reports: " email_address

# OpenAI API Key configuration
echo -e "\n${BLUE}🔑 OpenAI API Key Configuration${NC}"
echo -e "You need a valid OpenAI API key to use M.A.I.L. Sentinel."
echo -e "If you don't have one yet, visit: ${CYAN}https://platform.openai.com/api-keys${NC}"
read -r -sp "Enter your OpenAI API key: " openai_key
echo ""

# Advanced settings configuration
echo -e "\n${BLUE}⚙️  Advanced Settings${NC}"
echo -e "M.A.I.L. Sentinel has several optional settings you can customize."
echo -e "Would you like to configure advanced settings, or use the defaults?"
read -r -p "Configure advanced settings? (y/n) [default: n]: " configure_advanced

# Set defaults
error_threshold=5
api_call_limit=5
time_window_hours=24
max_api_timeout=30
auto_ignore_threshold=3
debug_mode="false"
known_safe_patterns="gaia.bounces.google.com|amazonses.com|mailgun.net|sendgrid.net"

if [[ "$configure_advanced" =~ ^[Yy]$ ]]; then
    echo -e "\n${CYAN}Configuring advanced settings...${NC}"

    echo -e "\n${BOLD}Error Threshold${NC}"
    echo -e "Minimum error count before sending to OpenAI for AI analysis"
    read -r -p "Enter ERROR_THRESHOLD [default: 5]: " input_threshold
    error_threshold=${input_threshold:-5}

    echo -e "\n${BOLD}API Call Limit${NC}"
    echo -e "Maximum OpenAI API calls per script execution (to control costs)"
    read -r -p "Enter API_CALL_LIMIT [default: 5]: " input_api_limit
    api_call_limit=${input_api_limit:-5}

    echo -e "\n${BOLD}Time Window${NC}"
    echo -e "Hours of logs to analyze (looks back from current time)"
    read -r -p "Enter TIME_WINDOW_HOURS [default: 24]: " input_time_window
    time_window_hours=${input_time_window:-24}

    echo -e "\n${BOLD}Auto-Ignore Threshold${NC}"
    echo -e "IPs with fewer errors than this will be categorized as INFO (noise filtering)"
    read -r -p "Enter AUTO_IGNORE_THRESHOLD [default: 3]: " input_auto_ignore
    auto_ignore_threshold=${input_auto_ignore:-3}

    echo -e "\n${BOLD}Debug Mode${NC}"
    echo -e "Enable verbose debug output for troubleshooting"
    read -r -p "Enable debug mode? (true/false) [default: false]: " input_debug
    debug_mode=${input_debug:-false}

    echo -e "\n${BOLD}Known Safe Patterns${NC}"
    echo -e "Pipe-separated patterns to whitelist (e.g., trusted services like Google Bounces)"
    echo -e "Current default: gaia.bounces.google.com|amazonses.com|mailgun.net|sendgrid.net"
    read -r -p "Enter KNOWN_SAFE_PATTERNS [press Enter to use default]: " input_patterns
    if [ -n "$input_patterns" ]; then
        known_safe_patterns="$input_patterns"
    fi
fi

# Create the config.sh file
echo -e "\n${BOLD}Creating configuration file...${NC}"

# Generate the configuration file
cat > "$CONFIG_FILE" << EOF
#!/bin/bash
# Secure configuration file for M.A.I.L. Sentinel.
# Generated on $(date)

# Required: Email and API Configuration
export POSTFIX_REPORT_EMAIL="$email_address"  # Recipient email
export OPENAI_API_KEY="$openai_key"  # API key

# Optional: Thresholds and Limits
export ERROR_THRESHOLD=$error_threshold           # Minimum error count before sending to OpenAI
export API_CALL_LIMIT=$api_call_limit           # Maximum API calls per execution
export TIME_WINDOW_HOURS=$time_window_hours       # Hours of logs to analyze
export MAX_API_TIMEOUT=30         # OpenAI API timeout in seconds
export AUTO_IGNORE_THRESHOLD=$auto_ignore_threshold    # Ignore IPs with fewer errors than this

# Optional: Debug Mode
export MAIL_SENTINEL_DEBUG=$debug_mode  # Set to true for verbose debug output

# Optional: Known Safe Patterns (pipe-separated, no spaces)
export KNOWN_SAFE_PATTERNS="$known_safe_patterns"
EOF

# Set secure permissions
chmod 600 "$CONFIG_FILE"

echo -e "${GREEN}✅ Configuration file created with secure permissions (600)!${NC}"

# Cron job setup
echo -e "\n${BLUE}⏰ Cron Job Setup${NC}"
echo -e "Would you like to set up a cron job to run M.A.I.L. Sentinel automatically?"
read -r -p "Set up cron job? (y/n): " setup_cron

if [[ "$setup_cron" =~ ^[Yy]$ ]]; then
    echo -e "\nHow frequently would you like M.A.I.L. Sentinel to run?"
    echo -e "1) Hourly"
    echo -e "2) Every 6 hours"
    echo -e "3) Daily"
    echo -e "4) Custom"
    
    read -r -p "Enter your choice (1-4): " cron_choice
    
    case $cron_choice in
        1)
            cron_expression="0 * * * *"
            ;;
        2)
            cron_expression="0 */6 * * *"
            ;;
        3)
            cron_expression="0 0 * * *"
            ;;
        4)
            echo -e "Enter a custom cron expression:"
            read -r -p "Cron expression: " cron_expression
            ;;
        *)
            echo -e "${YELLOW}Invalid choice, defaulting to hourly.${NC}"
            cron_expression="0 * * * *"
            ;;
    esac
    
    # Write to temporary file and install new crontab
    crontab -l > mycron 2>/dev/null || true
    if ! grep -q "MAIL-Sentinel.sh" mycron; then
        echo "$cron_expression $SCRIPT_DIR/MAIL-Sentinel.sh" >> mycron
        crontab mycron
        rm mycron
        echo -e "${GREEN}✅ Cron job successfully installed!${NC}"
    else
        echo -e "${YELLOW}⚠️ A cron job for M.A.I.L. Sentinel already exists. Skipping...${NC}"
        rm mycron
    fi
else
    echo -e "${YELLOW}Skipping cron job setup.${NC}"
fi

# Make the main script executable
chmod +x "$SCRIPT_DIR/MAIL-Sentinel.sh"

echo -e "\n${GREEN}==================================${NC}"
echo -e "${GREEN}🎉 Installation Complete! 🎉${NC}"
echo -e "${GREEN}==================================${NC}"

echo -e "\n${BOLD}Next Steps:${NC}"
echo -e "1. You can run M.A.I.L. Sentinel manually with: ${YELLOW}$SCRIPT_DIR/MAIL-Sentinel.sh${NC}"
if [[ "$setup_cron" =~ ^[Yy]$ ]]; then
    echo -e "2. M.A.I.L. Sentinel will run automatically according to your cron settings"
fi
echo -e "3. To modify your configuration, edit: ${YELLOW}$CONFIG_FILE${NC}"

echo -e "\n${CYAN}Thank you for installing M.A.I.L. Sentinel!${NC}"
echo -e "${CYAN}For more information, visit our GitHub repository.${NC}"
echo -e "${CYAN}Happy monitoring! 📊 📧 🛡️${NC}\n"
