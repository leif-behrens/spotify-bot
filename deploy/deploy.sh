#!/bin/bash
# Secure Deployment Script for Spotify Bot on Raspberry Pi
# CWE-78: OS Command Injection Prevention, CWE-732: Incorrect Permission Assignment
# Security: OpenSSF Secure Coding - Shell Script Security

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'       # Secure Internal Field Separator

# Configuration - Override with environment variables
DEPLOY_USER="${DEPLOY_USER:-pi}"
DEPLOY_HOST="${DEPLOY_HOST:-raspberry.local}"
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
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Validate required environment variables
validate_environment() {
    local required_vars=("DEPLOY_HOST")

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done

    log_info "Environment validation passed"
}

# Test SSH connection
test_ssh_connection() {
    log_info "Testing SSH connection to ${DEPLOY_USER}@${DEPLOY_HOST}..."

    if ! ssh -o ConnectTimeout=10 -o BatchMode=yes "${DEPLOY_USER}@${DEPLOY_HOST}" exit 2>/dev/null; then
        log_error "SSH connection failed. Please ensure:"
        log_error "1. SSH key is configured: ssh-copy-id ${DEPLOY_USER}@${DEPLOY_HOST}"
        log_error "2. Host is reachable: ping ${DEPLOY_HOST}"
        log_error "3. SSH service is running on target"
        exit 1
    fi

    log_info "SSH connection successful"
}

# Create remote directory structure with secure permissions
setup_remote_directories() {
    log_info "Setting up directory structure on remote host..."

    # CWE-732: Secure directory permissions
    ssh "${DEPLOY_USER}@${DEPLOY_HOST}" "
        sudo mkdir -p ${APP_DIR}/{src,config,logs,data}
        sudo chown -R ${DEPLOY_USER}:${DEPLOY_USER} ${APP_DIR}
        chmod 750 ${APP_DIR}
        chmod 755 ${APP_DIR}/logs
        chmod 700 ${APP_DIR}/data
        chmod 644 ${APP_DIR}/config 2>/dev/null || true
    "

    log_info "Remote directories created with secure permissions"
}

# Sync application files with rsync (secure and efficient)
sync_application_files() {
    log_info "Syncing application files..."

    # CWE-78: Use absolute paths and validate rsync options
    local rsync_opts=(
        --archive
        --compress
        --delete
        --verbose
        --human-readable
        --exclude-from=.gitignore
        --exclude='.git'
        --exclude='venv'
        --exclude='*.pyc'
        --exclude='__pycache__'
        --exclude='data/.spotify_token'
        --exclude='data/.key'
        --exclude='logs/*.log'
    )

    if ! rsync "${rsync_opts[@]}" ./ "${DEPLOY_USER}@${DEPLOY_HOST}:${APP_DIR}/"; then
        log_error "File synchronization failed"
        exit 1
    fi

    log_info "Application files synchronized successfully"
}

# Setup Python virtual environment on remote host
setup_python_environment() {
    log_info "Setting up Python virtual environment..."

    ssh "${DEPLOY_USER}@${DEPLOY_HOST}" "
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
    "

    log_info "Python environment setup complete"
}

# Install/update systemd service
install_systemd_service() {
    log_info "Installing systemd service..."

    # Create systemd service file on remote host
    ssh "${DEPLOY_USER}@${DEPLOY_HOST}" "
        # Create service file with secure configuration
        sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << 'EOF'
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
ExecStart=${APP_DIR}/venv/bin/python main.py service start discovery
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
    "

    log_info "Systemd service installed and enabled"
}

# Deploy configuration with security validation
deploy_configuration() {
    log_info "Deploying production configuration..."

    # Check if production config exists
    if [[ ! -f "config/config.production.json" ]]; then
        log_warn "Production config not found. Creating template..."

        # Create production config template
        ssh "${DEPLOY_USER}@${DEPLOY_HOST}" "
            cd ${APP_DIR}
            cp config/config.json config/config.production.json

            # Update for production environment
            sed -i 's/\"debug\": true/\"debug\": false/g' config/config.production.json
            sed -i 's/\"level\": \"DEBUG\"/\"level\": \"INFO\"/g' config/config.production.json

            echo 'IMPORTANT: Update config/config.production.json with production values!'
        "
    else
        # Copy production config
        scp config/config.production.json "${DEPLOY_USER}@${DEPLOY_HOST}:${APP_DIR}/config/"
    fi

    # Set secure permissions on config files
    ssh "${DEPLOY_USER}@${DEPLOY_HOST}" "
        chmod 640 ${APP_DIR}/config/*.json
    "

    log_info "Configuration deployment complete"
}

# Restart services and verify deployment
restart_and_verify() {
    log_info "Restarting services and verifying deployment..."

    ssh "${DEPLOY_USER}@${DEPLOY_HOST}" "
        cd ${APP_DIR}

        # Stop existing services
        sudo systemctl stop ${SERVICE_NAME} 2>/dev/null || true

        # Kill any remaining processes
        pkill -f 'python.*main.py' || true

        # Start service
        sudo systemctl start ${SERVICE_NAME}

        # Check service status
        sleep 3
        if sudo systemctl is-active --quiet ${SERVICE_NAME}; then
            echo 'Service started successfully'
            sudo systemctl status ${SERVICE_NAME} --no-pager -l
        else
            echo 'Service failed to start!'
            sudo journalctl -u ${SERVICE_NAME} --no-pager -l --since='1 minute ago'
            exit 1
        fi
    "

    log_info "Deployment verification complete"
}

# Main deployment function
main() {
    log_info "Starting secure deployment of ${APP_NAME}..."
    log_info "Target: ${DEPLOY_USER}@${DEPLOY_HOST}:${APP_DIR}"

    validate_environment
    test_ssh_connection
    setup_remote_directories
    sync_application_files
    setup_python_environment
    install_systemd_service
    deploy_configuration
    restart_and_verify

    log_info "🚀 Deployment completed successfully!"
    log_info "Service status: ssh ${DEPLOY_USER}@${DEPLOY_HOST} 'sudo systemctl status ${SERVICE_NAME}'"
    log_info "View logs: ssh ${DEPLOY_USER}@${DEPLOY_HOST} 'sudo journalctl -u ${SERVICE_NAME} -f'"
}

# Handle script interruption gracefully
trap 'log_error "Deployment interrupted"; exit 130' INT TERM

# Run main function
main "$@"
