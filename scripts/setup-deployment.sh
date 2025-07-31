#!/bin/bash
# Setup script for Spotify Bot CI/CD deployment
# CWE-78: OS Command Injection Prevention

set -euo pipefail
IFS=$'\n\t'

# Colors
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
DEPLOY_USER="${DEPLOY_USER:-pi}"
DEPLOY_HOST="${DEPLOY_HOST:-}"
SSH_KEY_PATH="${SSH_KEY_PATH:-~/.ssh/id_ed25519}"

print_usage() {
    cat << EOF
🚀 Spotify Bot Deployment Setup

Usage: $0 [OPTIONS]

Options:
    -h, --host HOSTNAME     Raspberry Pi hostname or IP (required)
    -u, --user USERNAME     SSH username (default: pi)
    -k, --key PATH          SSH private key path (default: ~/.ssh/id_ed25519)
    --help                  Show this help message

Examples:
    $0 --host raspberry.local
    $0 --host 192.168.1.100 --user pi
    $0 -h mypi.local -u admin -k ~/.ssh/mykey

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            DEPLOY_HOST="$2"
            shift 2
            ;;
        -u|--user)
            DEPLOY_USER="$2"
            shift 2
            ;;
        -k|--key)
            SSH_KEY_PATH="$2"
            shift 2
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$DEPLOY_HOST" ]]; then
    log_error "Raspberry Pi hostname is required"
    print_usage
    exit 1
fi

setup_ssh_key() {
    log_info "Setting up SSH key for deployment..."

    # Check if SSH key exists
    if [[ ! -f "$SSH_KEY_PATH" ]]; then
        log_warn "SSH key not found at $SSH_KEY_PATH"
        read -p "Generate new SSH key? (y/N): " -n 1 -r
        echo

        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -C "deployment@spotify-bot"
            log_info "SSH key generated at $SSH_KEY_PATH"
        else
            log_error "SSH key is required for deployment"
            exit 1
        fi
    fi

    # Copy SSH key to Raspberry Pi
    log_info "Copying SSH key to $DEPLOY_USER@$DEPLOY_HOST..."
    ssh-copy-id -i "$SSH_KEY_PATH.pub" "$DEPLOY_USER@$DEPLOY_HOST"

    # Test SSH connection
    log_info "Testing SSH connection..."
    if ssh -o ConnectTimeout=10 -i "$SSH_KEY_PATH" "$DEPLOY_USER@$DEPLOY_HOST" exit; then
        log_info "✅ SSH connection successful"
    else
        log_error "❌ SSH connection failed"
        exit 1
    fi
}

prepare_raspberry_pi() {
    log_info "Preparing Raspberry Pi for deployment..."

    ssh -i "$SSH_KEY_PATH" "$DEPLOY_USER@$DEPLOY_HOST" << 'EOF'
        # Update system
        echo "📦 Updating system packages..."
        sudo apt update && sudo apt upgrade -y

        # Install required packages
        echo "🔧 Installing Python and dependencies..."
        sudo apt install -y python3.11 python3.11-venv python3-pip git rsync

        # Create application directory
        echo "📁 Creating application directory..."
        sudo mkdir -p /opt/spotify-bot
        sudo chown pi:pi /opt/spotify-bot
        chmod 750 /opt/spotify-bot

        echo "✅ Raspberry Pi preparation complete"
EOF

    log_info "✅ Raspberry Pi is ready for deployment"
}

generate_github_secrets() {
    log_info "Generating GitHub Secrets configuration..."

    cat << EOF > github-secrets.txt
📋 GitHub Secrets Configuration

Add these secrets to your GitHub repository:
Settings → Secrets and variables → Actions → New repository secret

Required Secrets:
=================

DEPLOY_HOST
Value: $DEPLOY_HOST

DEPLOY_SSH_KEY
Value: (paste the content of $SSH_KEY_PATH - the private key)

SMTP_PASSWORD
Value: (your Gmail App Password)

SENDER_EMAIL
Value: (your Gmail address for notifications)

RECIPIENT_EMAIL
Value: (email address to receive alerts)

Optional Secrets:
=================

APP_URL
Value: http://$DEPLOY_HOST:4444

📖 For detailed setup instructions, see DEPLOYMENT.md

EOF

    log_info "✅ GitHub secrets configuration saved to github-secrets.txt"
}

test_local_deployment() {
    log_info "Testing local deployment script..."

    if [[ ! -f "deploy/deploy.sh" ]]; then
        log_error "Deployment script not found. Run this from the project root directory."
        exit 1
    fi

    # Make deployment script executable
    chmod +x deploy/deploy.sh

    # Test deployment (dry run)
    log_info "Running deployment test..."
    DEPLOY_HOST="$DEPLOY_HOST" DEPLOY_USER="$DEPLOY_USER" ./deploy/deploy.sh

    log_info "✅ Local deployment test completed"
}

main() {
    log_info "🚀 Starting Spotify Bot deployment setup..."
    log_info "Target: $DEPLOY_USER@$DEPLOY_HOST"

    # Check if we're in the right directory
    if [[ ! -f "main.py" || ! -d "src" ]]; then
        log_error "Please run this script from the Spotify Bot project root directory"
        exit 1
    fi

    setup_ssh_key
    prepare_raspberry_pi
    generate_github_secrets
    test_local_deployment

    log_info "🎉 Deployment setup completed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Push your code to GitHub"
    log_info "2. Add the secrets from github-secrets.txt to your repository"
    log_info "3. Push to main branch to trigger automatic deployment"
    log_info ""
    log_info "📖 For more details, see DEPLOYMENT.md"
}

# Handle interruption gracefully
trap 'log_error "Setup interrupted"; exit 130' INT TERM

main "$@"
