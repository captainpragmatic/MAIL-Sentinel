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
dependencies=("jq" "curl" "tac" "mail" "sendmail" "awk" "sed")
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
read -p "Enter the email address to receive reports: " email_address

# OpenAI API Key configuration
echo -e "\n${BLUE}🔑 OpenAI API Key Configuration${NC}"
echo -e "You need a valid OpenAI API key to use M.A.I.L. Sentinel."
echo -e "If you don't have one yet, visit: ${CYAN}https://platform.openai.com/api-keys${NC}"
read -sp "Enter your OpenAI API key: " openai_key
echo ""

# Create the config.sh file
echo -e "\n${BOLD}Creating configuration file...${NC}"

# Generate the configuration file
cat > "$CONFIG_FILE" << EOF
#!/bin/bash
# Secure configuration file for M.A.I.L. Sentinel.
# Generated on $(date)
export POSTFIX_REPORT_EMAIL="$email_address"  # Recipient email
export OPENAI_API_KEY="$openai_key"  # API key
EOF

# Set secure permissions
chmod 600 "$CONFIG_FILE"

echo -e "${GREEN}✅ Configuration file created with secure permissions (600)!${NC}"

# Cron job setup
echo -e "\n${BLUE}⏰ Cron Job Setup${NC}"
echo -e "Would you like to set up a cron job to run M.A.I.L. Sentinel automatically?"
read -p "Set up cron job? (y/n): " setup_cron

if [[ "$setup_cron" =~ ^[Yy]$ ]]; then
    echo -e "\nHow frequently would you like M.A.I.L. Sentinel to run?"
    echo -e "1) Hourly"
    echo -e "2) Every 6 hours"
    echo -e "3) Daily"
    echo -e "4) Custom"
    
    read -p "Enter your choice (1-4): " cron_choice
    
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
            read -p "Cron expression: " cron_expression
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
