#!/bin/bash
# Local Deployment Script for Spotify Bot on Raspberry Pi
# CWE-78: OS Command Injection Prevention, CWE-732: Incorrect Permission Assignment
# Security: OpenSSF Secure Coding - Shell Script Security

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'       # Secure Internal Field Separator

# Configuration - Override with environment variables
DEPLOY_USER="${DEPLOY_USER:-$(whoami)}"
APP_NAME="${APP_NAME:-spotify-bot}"
APP_DIR="${APP_DIR:-/opt/${APP_NAME}}"
SERVICE_NAME="${SERVICE_NAME:-spotify-bot}"
PYTHON_VERSION="${PYTHON_VERSION:-3.11}"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Logging functions - CWE-532: Information Exposure Prevention
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root when needed
check_sudo() {
    if [[ $EUID -ne 0 ]] && [[ "$1" == "require" ]]; then
        log_error "This operation requires sudo privileges"
        exit 1
    fi
}

# Create directory structure with secure permissions
setup_directories() {
    log_info "Setting up directory structure..."

    # CWE-732: Secure directory permissions
    sudo mkdir -p ${APP_DIR}/{src,config,logs,data}
    sudo chown -R ${DEPLOY_USER}:${DEPLOY_USER} ${APP_DIR}
    chmod 750 ${APP_DIR}
    chmod 755 ${APP_DIR}/logs
    chmod 700 ${APP_DIR}/data
    chmod 755 ${APP_DIR}/config

    log_info "Directories created with secure permissions"
}

# Copy application files
copy_application_files() {
    log_info "Copying application files..."

    # Get the current directory (should be the project root)
    local source_dir="$(pwd)"

    # Copy files excluding development artifacts
    sudo rsync -av \
        --exclude='.git' \
        --exclude='venv' \
        --exclude='*.pyc' \
        --exclude='__pycache__' \
        --exclude='data/.spotify_token' \
        --exclude='data/.key' \
        --exclude='logs/*.log' \
        --exclude='.env' \
        "${source_dir}/" "${APP_DIR}/"

    # Fix ownership after copy
    sudo chown -R ${DEPLOY_USER}:${DEPLOY_USER} ${APP_DIR}

    log_info "Application files copied successfully"
}

# Setup Python virtual environment
setup_python_environment() {
    log_info "Setting up Python virtual environment..."

    cd ${APP_DIR}

    # Remove old venv if exists
    rm -rf venv

    # Create new virtual environment
    python${PYTHON_VERSION} -m venv venv || python3 -m venv venv

    # Upgrade pip and install requirements
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt

    # Set secure permissions on venv
    chmod -R 750 venv

    log_info "Python environment setup complete"
}

# Install/update systemd service
install_systemd_service() {
    log_info "Installing systemd service..."

    # Create service file with secure configuration
    sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << EOF
[Unit]
Description=Spotify Auto-Discovery Bot
After=network.target
Wants=network.target

[Service]
Type=simple
User=${DEPLOY_USER}
Group=${DEPLOY_USER}
WorkingDirectory=${APP_DIR}
Environment=PATH=${APP_DIR}/venv/bin
ExecStart=${APP_DIR}/venv/bin/python main.py start discovery
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening - CWE-250: Execution with Unnecessary Privileges
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${APP_DIR}/data ${APP_DIR}/logs
CapabilityBoundingSet=

# Resource limits - CWE-400: Resource Exhaustion Prevention
LimitNOFILE=1024
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable ${SERVICE_NAME}

    log_info "Systemd service installed and enabled"
}

# Deploy configuration with security validation
deploy_configuration() {
    log_info "Deploying production configuration..."

    cd ${APP_DIR}

    # Check if production config exists
    if [[ ! -f "config/config.production.json" ]]; then
        log_warn "Production config not found. Creating template..."

        # Create production config template
        cp config/config.json config/config.production.json

        # Update for production environment using python for JSON safety
        python3 -c "
import json
try:
    with open('config/config.production.json', 'r') as f:
        config = json.load(f)

    # Update for production
    config['callback_server']['debug'] = False
    config['logging']['level'] = 'INFO'
    config['logging']['console_enabled'] = False

    with open('config/config.production.json', 'w') as f:
        json.dump(config, f, indent=2)

    print('Production config template created')
except Exception as e:
    print(f'Error updating config: {e}')
"
        log_warn "IMPORTANT: Update config/config.production.json with production values!"
    fi

    # Set secure permissions on config files
    chmod 640 config/*.json

    log_info "Configuration deployment complete"
}

# Create .env template if it doesn't exist
create_env_template() {
    log_info "Checking environment configuration..."

    if [[ ! -f "${APP_DIR}/.env" ]]; then
        log_warn "Creating .env template..."

        cat > ${APP_DIR}/.env << 'EOF'
# Spotify API Credentials (Required)
# Get these from: https://developer.spotify.com/dashboard/applications
SPOTIFY_CLIENT_ID=your_client_id_here
SPOTIFY_CLIENT_SECRET=your_client_secret_here
SPOTIFY_REDIRECT_URI=http://localhost:4444/callback

# Email Configuration (Optional - for notifications)
SENDER_EMAIL=your_email@gmail.com
SENDER_PASSWORD=your_app_password_here
RECIPIENT_EMAIL=notification_recipient@gmail.com
EOF
        chmod 600 ${APP_DIR}/.env
        chown ${DEPLOY_USER}:${DEPLOY_USER} ${APP_DIR}/.env

        log_warn "IMPORTANT: Edit ${APP_DIR}/.env with your Spotify credentials!"
    fi
}

# Restart services and verify deployment
restart_and_verify() {
    log_info "Restarting services and verifying deployment..."

    cd ${APP_DIR}

    # Stop existing services
    sudo systemctl stop ${SERVICE_NAME} 2>/dev/null || true

    # Kill any remaining processes
    sudo pkill -f 'python.*main.py' || true

    # Start service
    sudo systemctl start ${SERVICE_NAME}

    # Check service status
    sleep 3
    if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
        log_info "Service started successfully"
        sudo systemctl status ${SERVICE_NAME} --no-pager -l
    else
        log_error "Service failed to start!"
        sudo journalctl -u ${SERVICE_NAME} --no-pager -l --since='1 minute ago'
        return 1
    fi

    log_info "Deployment verification complete"
}

# Main deployment function
main() {
    log_info "Starting local deployment of ${APP_NAME}..."
    log_info "Target directory: ${APP_DIR}"
    log_info "Service user: ${DEPLOY_USER}"

    # Check if we're in the right directory
    if [[ ! -f "main.py" ]] || [[ ! -f "requirements.txt" ]]; then
        log_error "Please run this script from the spotify-bot project directory"
        exit 1
    fi

    setup_directories
    copy_application_files
    setup_python_environment
    install_systemd_service
    deploy_configuration
    create_env_template
    restart_and_verify

    log_info "🚀 Local deployment completed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Edit ${APP_DIR}/.env with your Spotify credentials"
    log_info "2. Run: cd ${APP_DIR} && ./venv/bin/python main.py auth"
    log_info "3. Check service: sudo systemctl status ${SERVICE_NAME}"
    log_info "4. View logs: sudo journalctl -u ${SERVICE_NAME} -f"
}

# Handle script interruption gracefully
trap 'log_error "Deployment interrupted"; exit 130' INT TERM

# Check if running from project directory
if [[ ! -f "main.py" ]]; then
    log_error "Please run this script from the spotify-bot project directory"
    exit 1
fi

# Run main function
main "$@"
