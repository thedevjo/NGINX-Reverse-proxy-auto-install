#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/nginx-reverse-proxy-installer.log"

# Function to log messages
log_message() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to print colored output
print_status() {
    case $1 in
        "success") echo -e "${GREEN}$2${NC}" | tee -a "$LOG_FILE" ;;
        "error") echo -e "${RED}$2${NC}" | tee -a "$LOG_FILE" ;;
        "warning") echo -e "${YELLOW}$2${NC}" | tee -a "$LOG_FILE" ;;
        "info") echo -e "${BLUE}$2${NC}" | tee -a "$LOG_FILE" ;;
    esac
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "error" "This script must be run as root"
        exit 1
    fi
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v nginx &> /dev/null; then
        missing_deps+=("nginx")
    fi
    
    if ! command -v certbot &> /dev/null && [[ "$ENABLE_SSL" == "yes" ]]; then
        missing_deps+=("certbot")
    fi
    
    if [[ ${#missing_deps[@]} -ne 0 ]]; then
        print_status "warning" "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
    
    return 0
}

# Function to install dependencies
install_dependencies() {
    print_status "info" "Installing dependencies..."
    
    # Detect package manager
    if command -v apt &> /dev/null; then
        apt update >> "$LOG_FILE" 2>&1
        apt install -y nginx >> "$LOG_FILE" 2>&1
        
        if [[ "$ENABLE_SSL" == "yes" ]]; then
            apt install -y certbot python3-certbot-nginx >> "$LOG_FILE" 2>&1
        fi
        
    elif command -v yum &> /dev/null; then
        yum install -y epel-release >> "$LOG_FILE" 2>&1
        yum install -y nginx >> "$LOG_FILE" 2>&1
        
        if [[ "$ENABLE_SSL" == "yes" ]]; then
            yum install -y certbot python3-certbot-nginx >> "$LOG_FILE" 2>&1
        fi
        
    elif command -v dnf &> /dev/null; then
        dnf install -y nginx >> "$LOG_FILE" 2>&1
        
        if [[ "$ENABLE_SSL" == "yes" ]]; then
            dnf install -y certbot python3-certbot-nginx >> "$LOG_FILE" 2>&1
        fi
        
    else
        print_status "error" "Unsupported package manager"
        exit 1
    fi
    
    if [[ $? -eq 0 ]]; then
        print_status "success" "Dependencies installed successfully"
    else
        print_status "error" "Failed to install dependencies"
        exit 1
    fi
}

# Function to get user input
get_user_input() {
    echo "=============================================="
    echo "   NGINX Reverse Proxy Configuration Wizard   "
    echo "=============================================="
    echo ""
    
    # Get backend server details
    read -p "Enter the backend server IP address: " BACKEND_IP
    read -p "Enter the backend server port: " BACKEND_PORT
    
    # Get domain name
    read -p "Enter the domain name for the reverse proxy (e.g., example.com): " DOMAIN_NAME
    
    # SSL configuration
    read -p "Enable HTTPS/SSL? (yes/no) [yes]: " ENABLE_SSL
    ENABLE_SSL=${ENABLE_SSL:-yes}
    
    if [[ "$ENABLE_SSL" == "yes" ]]; then
        read -p "Enter email for SSL certificate (for renewal notices): " SSL_EMAIL
    fi
    
    # Additional options
    read -p "Enable WebSocket support? (yes/no) [yes]: " WEBSOCKET_SUPPORT
    WEBSOCKET_SUPPORT=${WEBSOCKET_SUPPORT:-yes}
    
    read -p "Enable Gzip compression? (yes/no) [yes]: " GZIP_COMPRESSION
    GZIP_COMPRESSION=${GZIP_COMPRESSION:-yes}
    
    read -p "Enable access logging? (yes/no) [yes]: " ACCESS_LOGGING
    ACCESS_LOGGING=${ACCESS_LOGGING:-yes}
    
    echo ""
}

# Function to validate input
validate_input() {
    if [[ -z "$BACKEND_IP" || -z "$BACKEND_PORT" || -z "$DOMAIN_NAME" ]]; then
        print_status "error" "All fields are required"
        return 1
    fi
    
    if ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [ "$BACKEND_PORT" -lt 1 ] || [ "$BACKEND_PORT" -gt 65535 ]; then
        print_status "error" "Port must be a number between 1 and 65535"
        return 1
    fi
    
    if [[ "$ENABLE_SSL" == "yes" && -z "$SSL_EMAIL" ]]; then
        print_status "error" "Email is required for SSL certificate"
        return 1
    fi
    
    return 0
}

# Function to add WebSocket support to main NGINX config
add_websocket_support() {
    local main_config="/etc/nginx/nginx.conf"
    
    # Check if the map block already exists
    if ! grep -q "connection_upgrade" "$main_config"; then
        print_status "info" "Adding WebSocket support to main NGINX configuration..."
        
        # Add the map block before the http block
        sed -i '/http {/i \# WebSocket support\nmap \$http_upgrade \$connection_upgrade {\n    default upgrade;\n    '\'''\''      close;\n}\n' "$main_config"
        
        if [[ $? -eq 0 ]]; then
            print_status "success" "WebSocket support added to main configuration"
        else
            print_status "warning" "Could not automatically add WebSocket support. You may need to manually add it."
        fi
    fi
}

# Function to create NGINX configuration
create_nginx_config() {
    local config_file="/etc/nginx/sites-available/$DOMAIN_NAME"
    
    # Create config directory if it doesn't exist
    if [[ ! -d "/etc/nginx/sites-available" ]]; then
        mkdir -p /etc/nginx/sites-available
        mkdir -p /etc/nginx/sites-enabled
    fi
    
    # Add WebSocket support if needed
    if [[ "$WEBSOCKET_SUPPORT" == "yes" ]]; then
        add_websocket_support
    fi
    
    print_status "info" "Creating NGINX configuration..."
    
    # Create the configuration file
    cat > "$config_file" << EOF
# Reverse Proxy Configuration for $DOMAIN_NAME
# Generated on $(date)

server {
    listen 80;
    server_name $DOMAIN_NAME;
    
    # Access logging
    $(if [[ "$ACCESS_LOGGING" == "yes" ]]; then
        echo "access_log /var/log/nginx/${DOMAIN_NAME}_access.log;"
        echo "error_log /var/log/nginx/${DOMAIN_NAME}_error.log;"
    else
        echo "access_log off;"
        echo "error_log /var/log/nginx/${DOMAIN_NAME}_error.log;"
    fi)
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Proxy settings
    location / {
        proxy_pass http://$BACKEND_IP:$BACKEND_PORT;
        proxy_http_version 1.1;
        $(if [[ "$WEBSOCKET_SUPPORT" == "yes" ]]; then
            echo "proxy_set_header Upgrade \$http_upgrade;"
            echo "proxy_set_header Connection \"upgrade\";"
        else
            echo "# proxy_set_header Upgrade \$http_upgrade;"
            echo "# proxy_set_header Connection \"upgrade\";"
        fi)
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
    
    # Block common vulnerabilities
    location ~* /\.env {
        deny all;
        return 404;
    }
    
    location ~* /\.git {
        deny all;
        return 404;
    }
}
EOF

    # Add SSL section if enabled
    if [[ "$ENABLE_SSL" == "yes" ]]; then
        cat >> "$config_file" << SSL_EOF

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name $DOMAIN_NAME;
    
    # SSL certificates will be managed by Certbot
    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Access logging
    $(if [[ "$ACCESS_LOGGING" == "yes" ]]; then
        echo "access_log /var/log/nginx/${DOMAIN_NAME}_ssl_access.log;"
        echo "error_log /var/log/nginx/${DOMAIN_NAME}_ssl_error.log;"
    else
        echo "access_log off;"
        echo "error_log /var/log/nginx/${DOMAIN_NAME}_ssl_error.log;"
    fi)
    
    # Proxy settings
    location / {
        proxy_pass http://$BACKEND_IP:$BACKEND_PORT;
        proxy_http_version 1.1;
        $(if [[ "$WEBSOCKET_SUPPORT" == "yes" ]]; then
            echo "proxy_set_header Upgrade \$http_upgrade;"
            echo "proxy_set_header Connection \"upgrade\";"
        else
            echo "# proxy_set_header Upgrade \$http_upgrade;"
            echo "# proxy_set_header Connection \"upgrade\";"
        fi)
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
SSL_EOF
    fi

    # Enable the site
    if [[ -f "/etc/nginx/sites-enabled/$DOMAIN_NAME" ]]; then
        rm "/etc/nginx/sites-enabled/$DOMAIN_NAME"
    fi
    ln -s "$config_file" "/etc/nginx/sites-enabled/$DOMAIN_NAME"
    
    print_status "success" "NGINX configuration created"
}

# Function to obtain SSL certificate
obtain_ssl_certificate() {
    if [[ "$ENABLE_SSL" != "yes" ]]; then
        return 0
    fi
    
    print_status "info" "Obtaining SSL certificate from Let's Encrypt..."
    
    # Use --webroot method instead of stopping NGINX
    if certbot certonly --webroot --non-interactive --agree-tos \
        --email "$SSL_EMAIL" -d "$DOMAIN_NAME" \
        --webroot-path="/var/www/html" >> "$LOG_FILE" 2>&1; then
        print_status "success" "SSL certificate obtained successfully"
        
        # Setup automatic renewal
        (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
        print_status "info" "SSL certificate auto-renewal configured"
    else
        print_status "error" "Failed to obtain SSL certificate"
        print_status "warning" "Continuing without SSL. You can manually obtain certificate later with:"
        print_status "info" "certbot certonly --nginx -d $DOMAIN_NAME"
        ENABLE_SSL="no"
    fi
}

# Function to configure firewall
configure_firewall() {
    print_status "info" "Configuring firewall..."
    
    # Check if ufw is available
    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp >> "$LOG_FILE" 2>&1
        if [[ "$ENABLE_SSL" == "yes" ]]; then
            ufw allow 443/tcp >> "$LOG_FILE" 2>&1
        fi
        ufw reload >> "$LOG_FILE" 2>&1
        
    # Check if firewalld is available
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=80/tcp >> "$LOG_FILE" 2>&1
        if [[ "$ENABLE_SSL" == "yes" ]]; then
            firewall-cmd --permanent --add-port=443/tcp >> "$LOG_FILE" 2>&1
        fi
        firewall-cmd --reload >> "$LOG_FILE" 2>&1
        
    else
        print_status "warning" "No supported firewall manager found. Please manually open ports:"
        print_status "info" "Port 80 (HTTP) needs to be open"
        if [[ "$ENABLE_SSL" == "yes" ]]; then
            print_status "info" "Port 443 (HTTPS) needs to be open"
        fi
        return 1
    fi
    
    print_status "success" "Firewall configured successfully"
}

# Function to test NGINX configuration
test_nginx_config() {
    print_status "info" "Testing NGINX configuration..."
    
    if nginx -t >> "$LOG_FILE" 2>&1; then
        print_status "success" "NGINX configuration test passed"
        return 0
    else
        print_status "error" "NGINX configuration test failed. Check $LOG_FILE for details."
        return 1
    fi
}

# Function to restart NGINX
restart_nginx() {
    print_status "info" "Restarting NGINX..."
    
    if systemctl restart nginx >> "$LOG_FILE" 2>&1; then
        print_status "success" "NGINX restarted successfully"
        return 0
    else
        print_status "error" "Failed to restart NGINX"
        return 1
    fi
}

# Function to display summary
display_summary() {
    echo ""
    echo "=============================================="
    echo "           INSTALLATION COMPLETE              "
    echo "=============================================="
    echo ""
    echo "Reverse Proxy Configuration Summary:"
    echo "------------------------------------"
    echo "Backend Server: $BACKEND_IP:$BACKEND_PORT"
    echo "Domain Name: $DOMAIN_NAME"
    echo "HTTPS/SSL: $ENABLE_SSL"
    echo "WebSocket Support: $WEBSOCKET_SUPPORT"
    echo "Gzip Compression: $GZIP_COMPRESSION"
    echo ""
    echo "Next Steps:"
    echo "-----------"
    echo "1. Ensure your domain $DOMAIN_NAME points to this server's IP"
    
    if [[ "$ENABLE_SSL" != "yes" ]]; then
        echo "2. To enable SSL later, run: certbot --nginx -d $DOMAIN_NAME"
    fi
    
    echo "3. Check logs: /var/log/nginx/${DOMAIN_NAME}_*.log"
    echo "4. Configuration file: /etc/nginx/sites-available/$DOMAIN_NAME"
    echo ""
    echo "Test your setup by visiting:"
    if [[ "$ENABLE_SSL" == "yes" ]]; then
        echo "HTTPS: https://$DOMAIN_NAME"
    else
        echo "HTTP: http://$DOMAIN_NAME"
    fi
    echo ""
    echo "Log file: $LOG_FILE"
    echo "=============================================="
}

# Main execution
main() {
    check_root
    
    # Initialize log file
    > "$LOG_FILE"
    log_message "Starting NGINX Reverse Proxy installation"
    
    # Get user input
    get_user_input
    
    # Validate input
    if ! validate_input; then
        print_status "error" "Input validation failed. Please run the script again."
        exit 1
    fi
    
    # Check and install dependencies
    if ! check_dependencies; then
        install_dependencies
    fi
    
    # Create NGINX configuration
    create_nginx_config
    
    # Configure firewall
    configure_firewall
    
    # Obtain SSL certificate if enabled
    obtain_ssl_certificate
    
    # Test configuration
    if ! test_nginx_config; then
        print_status "error" "Configuration test failed. Aborting."
        exit 1
    fi
    
    # Restart NGINX
    if ! restart_nginx; then
        print_status "error" "Failed to restart NGINX. Check logs for details."
        exit 1
    fi
    
    # Display summary
    display_summary
    
    log_message "Installation completed successfully"
}

# Handle script interruption
trap 'echo -e "\n${RED}Installation interrupted by user${NC}"; exit 1' INT

# Run main function
main "$@"
