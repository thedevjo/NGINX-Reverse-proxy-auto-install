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

# Function to show welcome message and warning
show_welcome() {
    echo "=============================================="
    echo "   NGINX Reverse Proxy Configuration Wizard   "
    echo "=============================================="
    echo ""
    
    print_status "warning" "IMPORTANT: Before continuing, make sure you have:"
    echo "1. Created an A record in your DNS for your domain pointing to this server's IP"
    echo "2. Allowed time for DNS propagation (can take up to 24 hours)"
    echo ""
    read -p "Press Enter to continue once your DNS is configured..." 
    echo ""
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "error" "This script must be run as root. Please use: sudo $0"
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
    print_status "info" "Installing required packages..."
    
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
        print_status "error" "Unsupported package manager. Please install NGINX manually first."
        exit 1
    fi
    
    if [[ $? -eq 0 ]]; then
        print_status "success" "Packages installed successfully"
    else
        print_status "error" "Failed to install required packages"
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
    read -p "Enter the backend server IP address (the server you want to proxy to): " BACKEND_IP
    read -p "Enter the backend server port (e.g., 3000, 8080, etc.): " BACKEND_PORT
    
    # Get domain name
    read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
    
    # SSL configuration
    read -p "Enable HTTPS/SSL? (yes/no) [yes]: " ENABLE_SSL
    ENABLE_SSL=${ENABLE_SSL:-yes}
    
    if [[ "$ENABLE_SSL" == "yes" ]]; then
        read -p "Enter your email for SSL certificate (for renewal notices): " SSL_EMAIL
        read -p "Force HTTPS redirect? (yes/no) [yes]: " FORCE_HTTPS
        FORCE_HTTPS=${FORCE_HTTPS:-yes}
    fi
    
    # Additional options with default "no"
    echo ""
    echo "Advanced options (if you don't know what these are, just press Enter for default):"
    read -p "Enable WebSocket support? (yes/no) [no]: " WEBSOCKET_SUPPORT
    WEBSOCKET_SUPPORT=${WEBSOCKET_SUPPORT:-no}
    
    read -p "Enable Gzip compression? (yes/no) [no]: " GZIP_COMPRESSION
    GZIP_COMPRESSION=${GZIP_COMPRESSION:-no}
    
    read -p "Enable detailed access logging? (yes/no) [no]: " ACCESS_LOGGING
    ACCESS_LOGGING=${ACCESS_LOGGING:-no}
    
    echo ""
}

# Function to validate input
validate_input() {
    if [[ -z "$BACKEND_IP" || -z "$BACKEND_PORT" || -z "$DOMAIN_NAME" ]]; then
        print_status "error" "Error: All fields are required. Please provide all information."
        return 1
    fi
    
    if ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [ "$BACKEND_PORT" -lt 1 ] || [ "$BACKEND_PORT" -gt 65535 ]; then
        print_status "error" "Error: Port must be a valid number between 1 and 65535"
        return 1
    fi
    
    if [[ "$ENABLE_SSL" == "yes" && -z "$SSL_EMAIL" ]]; then
        print_status "error" "Error: Email address is required for SSL certificate registration"
        return 1
    fi
    
    return 0
}

# Function to add WebSocket support to main NGINX config
add_websocket_support() {
    local main_config="/etc/nginx/nginx.conf"
    
    # Check if the map block already exists
    if ! grep -q "connection_upgrade" "$main_config"; then
        print_status "info" "Configuring WebSocket support..."
        
        # Add the map block before the http block
        sed -i '/http {/i \# WebSocket support\nmap \$http_upgrade \$connection_upgrade {\n    default upgrade;\n    '\'''\''      close;\n}\n' "$main_config"
        
        if [[ $? -eq 0 ]]; then
            print_status "success" "WebSocket support configured successfully"
        else
            print_status "warning" "Could not automatically configure WebSocket support. You may need to add it manually to nginx.conf"
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
    
    print_status "info" "Creating reverse proxy configuration..."
    
    # Create the configuration file
    cat > "$config_file" << EOF
# Reverse Proxy Configuration for $DOMAIN_NAME
# Generated on $(date)

server {
    listen 80;
    server_name $DOMAIN_NAME;
    
    $(if [[ "$ENABLE_SSL" == "yes" && "$FORCE_HTTPS" == "yes" ]]; then
        echo "    # Redirect HTTP to HTTPS"
        echo "    return 301 https://\$host\$request_uri;"
    else
        echo "    # Access logging"
        if [[ "$ACCESS_LOGGING" == "yes" ]]; then
            echo "    access_log /var/log/nginx/${DOMAIN_NAME}_access.log;"
            echo "    error_log /var/log/nginx/${DOMAIN_NAME}_error.log;"
        else
            echo "    access_log off;"
            echo "    error_log /var/log/nginx/${DOMAIN_NAME}_error.log;"
        fi
        
        echo ""
        echo "    # Security headers"
        echo "    add_header X-Frame-Options DENY always;"
        echo "    add_header X-Content-Type-Options nosniff always;"
        echo "    add_header X-XSS-Protection \"1; mode=block\" always;"
        echo ""
        echo "    # Proxy settings"
        echo "    location / {"
        echo "        proxy_pass http://$BACKEND_IP:$BACKEND_PORT;"
        echo "        proxy_http_version 1.1;"
        if [[ "$WEBSOCKET_SUPPORT" == "yes" ]]; then
            echo "        proxy_set_header Upgrade \$http_upgrade;"
            echo "        proxy_set_header Connection \"upgrade\";"
        else
            echo "        # proxy_set_header Upgrade \$http_upgrade;"
            echo "        # proxy_set_header Connection \"upgrade\";"
        fi
        echo "        proxy_set_header Host \$host;"
        echo "        proxy_set_header X-Real-IP \$remote_addr;"
        echo "        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;"
        echo "        proxy_set_header X-Forwarded-Proto \$scheme;"
        echo ""
        echo "        # Timeout settings"
        echo "        proxy_connect_timeout 60s;"
        echo "        proxy_send_timeout 60s;"
        echo "        proxy_read_timeout 60s;"
        echo ""
        echo "        # Buffer settings"
        echo "        proxy_buffering on;"
        echo "        proxy_buffer_size 4k;"
        echo "        proxy_buffers 8 4k;"
        echo "    }"
    fi)
    
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
        echo "    access_log /var/log/nginx/${DOMAIN_NAME}_ssl_access.log;"
        echo "    error_log /var/log/nginx/${DOMAIN_NAME}_ssl_error.log;"
    else
        echo "    access_log off;"
        echo "    error_log /var/log/nginx/${DOMAIN_NAME}_ssl_error.log;"
    fi)
    
    # Proxy settings
    location / {
        proxy_pass http://$BACKEND_IP:$BACKEND_PORT;
        proxy_http_version 1.1;
        $(if [[ "$WEBSOCKET_SUPPORT" == "yes" ]]; then
            echo "        proxy_set_header Upgrade \$http_upgrade;"
            echo "        proxy_set_header Connection \"upgrade\";"
        else
            echo "        # proxy_set_header Upgrade \$http_upgrade;"
            echo "        # proxy_set_header Connection \"upgrade\";"
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
    
    print_status "success" "Configuration file created successfully"
}

# Function to obtain SSL certificate
obtain_ssl_certificate() {
    if [[ "$ENABLE_SSL" != "yes" ]]; then
        return 0
    fi
    
    print_status "info" "Requesting SSL certificate from Let's Encrypt..."
    
    # Use --webroot method instead of stopping NGINX
    if certbot certonly --webroot --non-interactive --agree-tos \
        --email "$SSL_EMAIL" -d "$DOMAIN_NAME" \
        --webroot-path="/var/www/html" >> "$LOG_FILE" 2>&1; then
        print_status "success" "SSL certificate obtained successfully"
        
        # Setup automatic renewal
        (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
        print_status "info" "Automatic certificate renewal has been configured"
    else
        print_status "error" "Failed to obtain SSL certificate"
        print_status "warning" "Continuing without SSL. You can manually obtain a certificate later with:"
        print_status "info" "sudo certbot --nginx -d $DOMAIN_NAME"
        ENABLE_SSL="no"
    fi
}

# Function to configure firewall
configure_firewall() {
    print_status "info" "Configuring firewall rules..."
    
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
        print_status "warning" "No supported firewall manager found. Please ensure these ports are open:"
        print_status "info" "Port 80 (HTTP) must be open"
        if [[ "$ENABLE_SSL" == "yes" ]]; then
            print_status "info" "Port 443 (HTTPS) must be open"
        fi
        return 1
    fi
    
    print_status "success" "Firewall configured successfully"
}

# Function to test NGINX configuration
test_nginx_config() {
    print_status "info" "Testing configuration for errors..."
    
    if nginx -t >> "$LOG_FILE" 2>&1; then
        print_status "success" "Configuration test passed"
        return 0
    else
        print_status "error" "Configuration test failed. Please check the log file: $LOG_FILE"
        return 1
    fi
}

# Function to restart NGINX
restart_nginx() {
    print_status "info" "Applying configuration changes..."
    
    if systemctl restart nginx >> "$LOG_FILE" 2>&1; then
        print_status "success" "NGINX restarted successfully"
        return 0
    else
        print_status "error" "Failed to restart NGINX. Check system status with: systemctl status nginx"
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
    echo "Your reverse proxy has been successfully configured!"
    echo ""
    echo "Configuration Summary:"
    echo "----------------------"
    echo "Backend Server: $BACKEND_IP:$BACKEND_PORT"
    echo "Domain Name: $DOMAIN_NAME"
    echo "HTTPS/SSL: $( [[ "$ENABLE_SSL" == "yes" ]] && echo "Enabled" || echo "Disabled" )"
    if [[ "$ENABLE_SSL" == "yes" ]]; then
        echo "Force HTTPS: $( [[ "$FORCE_HTTPS" == "yes" ]] && echo "Enabled" || echo "Disabled" )"
    fi
    echo "WebSocket Support: $( [[ "$WEBSOCKET_SUPPORT" == "yes" ]] && echo "Enabled" || echo "Disabled" )"
    echo "Access Logging: $( [[ "$ACCESS_LOGGING" == "yes" ]] && echo "Enabled" || echo "Disabled" )"
    echo ""
    echo "Next Steps:"
    echo "-----------"
    echo "1. Ensure your DNS A record for $DOMAIN_NAME points to this server's IP"
    echo "2. Allow up to 24 hours for DNS propagation if you just created the record"
    
    if [[ "$ENABLE_SSL" != "yes" ]]; then
        echo "3. Enable SSL later with: sudo certbot --nginx -d $DOMAIN_NAME"
    fi
    
    echo "4. Check logs: /var/log/nginx/${DOMAIN_NAME}_*.log"
    echo "5. Configuration file: /etc/nginx/sites-available/$DOMAIN_NAME"
    echo ""
    echo "Test your setup by visiting:"
    if [[ "$ENABLE_SSL" == "yes" ]]; then
        echo "Secure: https://$DOMAIN_NAME"
    else
        echo "Regular: http://$DOMAIN_NAME"
    fi
    echo ""
    echo "Need help? Check the log file: $LOG_FILE"
    echo "=============================================="
}

# Main execution
main() {
    # Show welcome message and warning first
    show_welcome
    
    check_root
    
    # Initialize log file
    > "$LOG_FILE"
    log_message "Starting NGINX Reverse Proxy installation"
    
    # Get user input
    get_user_input
    
    # Validate input
    if ! validate_input; then
        print_status "error" "Please fix the errors above and run the script again."
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
        print_status "error" "Configuration test failed. Please check the errors above."
        exit 1
    fi
    
    # Restart NGINX
    if ! restart_nginx; then
        print_status "error" "Failed to restart NGINX. Please check the system logs."
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
