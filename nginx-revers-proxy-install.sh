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

# Function to validate yes/no input
validate_yes_no() {
    local input="$1"
    local default="$2"
    
    # Convert to lowercase for comparison
    input_lower=$(echo "$input" | tr '[:upper:]' '[:lower:]')
    
    if [[ -z "$input" && -n "$default" ]]; then
        echo "$default"
        return 0
    fi
    
    case "$input_lower" in
        "yes"|"y") echo "yes"; return 0 ;;
        "no"|"n") echo "no"; return 0 ;;
        *) return 1 ;;
    esac
}

# Function to validate email format
validate_email() {
    local email="$1"
    # Simple email validation regex
    if [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to extract IP from URL
extract_ip() {
    local input="$1"
    # Remove http://, https://, and everything after : or /
    echo "$input" | sed -e 's|^[^/]*//||' -e 's|[:/].*$||' -e 's|^.*@||'
}

# Function to extract port from URL
extract_port() {
    local input="$1"
    # Extract port number if present
    if echo "$input" | grep -q ':'; then
        echo "$input" | sed 's/^.*://' | sed 's/[^0-9].*$//'
    else
        echo "$input"
    fi
}

# Function to show main menu
show_menu() {
    echo "=============================================="
    echo "       NGINX Reverse Proxy Manager           "
    echo "=============================================="
    echo ""
    echo "1. Install Reverse Proxy"
    echo "2. Remove Reverse Proxy"
    echo "3. Exit"
    echo ""
    read -p "Select an option (1-3): " MENU_CHOICE
}

# Function to remove reverse proxy
remove_reverse_proxy() {
    echo ""
    echo "=============================================="
    echo "        Remove Reverse Proxy Configuration    "
    echo "=============================================="
    echo ""
    
    # List available sites
    if [[ ! -d "/etc/nginx/sites-available" ]]; then
        print_status "info" "No reverse proxy configurations found."
        return
    fi
    
    local sites=($(ls /etc/nginx/sites-available/ 2>/dev/null))
    if [[ ${#sites[@]} -eq 0 ]]; then
        print_status "info" "No reverse proxy configurations found."
        return
    fi
    
    echo "Available configurations:"
    for i in "${!sites[@]}"; do
        echo "$((i+1)). ${sites[$i]}"
    done
    echo ""
    
    read -p "Enter the number of the configuration to remove: " REMOVE_CHOICE
    
    if [[ ! "$REMOVE_CHOICE" =~ ^[0-9]+$ ]] || [ "$REMOVE_CHOICE" -lt 1 ] || [ "$REMOVE_CHOICE" -gt ${#sites[@]} ]; then
        print_status "error" "Invalid selection."
        return
    fi
    
    local selected_site="${sites[$((REMOVE_CHOICE-1))]}"
    
    # Confirm removal
    read -p "Are you sure you want to remove '$selected_site'? (yes/no): " CONFIRM_REMOVE
    if [[ ! "$CONFIRM_REMOVE" =~ ^[Yy][Ee][Ss]|[Yy]$ ]]; then
        print_status "info" "Removal cancelled."
        return
    fi
    
    # Remove configuration
    print_status "info" "Removing configuration for $selected_site..."
    
    # Remove from sites-enabled
    if [[ -f "/etc/nginx/sites-enabled/$selected_site" ]]; then
        rm -f "/etc/nginx/sites-enabled/$selected_site"
    fi
    
    # Remove from sites-available
    if [[ -f "/etc/nginx/sites-available/$selected_site" ]]; then
        rm -f "/etc/nginx/sites-available/$selected_site"
    fi
    
    # Test configuration
    if nginx -t >> "$LOG_FILE" 2>&1; then
        # Restart NGINX
        if systemctl restart nginx >> "$LOG_FILE" 2>&1; then
            print_status "success" "Reverse proxy configuration for '$selected_site' removed successfully."
        else
            print_status "error" "Failed to restart NGINX. Configuration was removed but NGINX needs manual restart."
        fi
    else
        print_status "error" "Configuration test failed after removal. Please check NGINX configuration manually."
    fi
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
    while true; do
        read -p "Enter the backend server IP address (the server you want to proxy to): " BACKEND_IP_INPUT
        if [[ -n "$BACKEND_IP_INPUT" ]]; then
            # Extract just the IP address
            BACKEND_IP=$(extract_ip "$BACKEND_IP_INPUT")
            if [[ -n "$BACKEND_IP" ]]; then
                break
            else
                print_status "error" "Could not extract valid IP address. Please try again."
            fi
        else
            print_status "error" "Backend server IP is required. Please try again."
        fi
    done
    
    while true; do
        read -p "Enter the backend server port (e.g., 3000, 8080, etc.): " BACKEND_PORT_INPUT
        if [[ -n "$BACKEND_PORT_INPUT" ]]; then
            # Extract just the port number
            BACKEND_PORT=$(extract_port "$BACKEND_PORT_INPUT")
            if [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] && [ "$BACKEND_PORT" -ge 1 ] && [ "$BACKEND_PORT" -le 65535 ]; then
                break
            else
                print_status "error" "Port must be a valid number between 1 and 65535. Please try again."
            fi
        else
            print_status "error" "Backend server port is required. Please try again."
        fi
    done
    
    # Get domain name
    while true; do
        read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
        if [[ -n "$DOMAIN_NAME" ]]; then
            break
        else
            print_status "error" "Domain name is required. Please try again."
        fi
    done
    
    # SSL configuration
    while true; do
        read -p "Enable HTTPS/SSL? (yes/no) [yes]: " SSL_INPUT
        ENABLE_SSL=$(validate_yes_no "$SSL_INPUT" "yes")
        if [[ $? -eq 0 ]]; then
            break
        else
            print_status "error" "Please enter 'yes' or 'no'. Please try again."
        fi
    done
    
    if [[ "$ENABLE_SSL" == "yes" ]]; then
        # Email validation with retry
        while true; do
            read -p "Enter your email for SSL certificate (for renewal notices): " SSL_EMAIL
            if validate_email "$SSL_EMAIL"; then
                break
            else
                print_status "error" "Invalid email format. Please enter a valid email address."
            fi
        done
        
        # Force HTTPS validation
        while true; do
            read -p "Force HTTPS redirect? (yes/no) [yes]: " HTTPS_INPUT
            FORCE_HTTPS=$(validate_yes_no "$HTTPS_INPUT" "yes")
            if [[ $? -eq 0 ]]; then
                break
            else
                print_status "error" "Please enter 'yes' or 'no'. Please try again."
            fi
        done
    fi
    
    # Additional options with default "no"
    echo ""
    echo "Advanced options (if you don't know what these are, just press Enter for default):"
    
    # WebSocket support validation
    while true; do
        read -p "Enable WebSocket support? (yes/no) [no]: " WS_INPUT
        WEBSOCKET_SUPPORT=$(validate_yes_no "$WS_INPUT" "no")
        if [[ $? -eq 0 ]]; then
            break
        else
            print_status "error" "Please enter 'yes' or 'no'. Please try again."
        fi
    done
    
    # Gzip compression validation
    while true; do
        read -p "Enable Gzip compression? (yes/no) [no]: " GZIP_INPUT
        GZIP_COMPRESSION=$(validate_yes_no "$GZIP_INPUT" "no")
        if [[ $? -eq 0 ]]; then
            break
        else
            print_status "error" "Please enter 'yes' or 'no'. Please try again."
        fi
    done
    
    # Access logging validation
    while true; do
        read -p "Enable detailed access logging? (yes/no) [no]: " LOG_INPUT
        ACCESS_LOGGING=$(validate_yes_no "$LOG_INPUT" "no")
        if [[ $? -eq 0 ]]; then
            break
        else
            print_status "error" "Please enter 'yes' or 'no'. Please try again."
        fi
    done
    
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
    
    # Create the configuration file with only HTTP block
    cat > "$config_file" << EOF
# Reverse Proxy Configuration for $DOMAIN_NAME
# Generated on $(date)

server {
    listen 80;
    server_name $DOMAIN_NAME;
    
    # Access logging
    $(if [[ "$ACCESS_LOGGING" == "yes" ]]; then
        echo "    access_log /var/log/nginx/${DOMAIN_NAME}_access.log;"
        echo "    error_log /var/log/nginx/${DOMAIN_NAME}_error.log;"
    else
        echo "    access_log off;"
        echo "    error_log /var/log/nginx/${DOMAIN_NAME}_error.log;"
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
        
        # Now add HTTPS configuration
        add_https_configuration
    else
        print_status "error" "Failed to obtain SSL certificate"
        print_status "warning" "Continuing without SSL. You can manually obtain a certificate later with:"
        print_status "info" "sudo certbot --nginx -d $DOMAIN_NAME"
        ENABLE_SSL="no"
    fi
}

# Function to add HTTPS configuration after certificate is obtained
add_https_configuration() {
    local config_file="/etc/nginx/sites-available/$DOMAIN_NAME"
    
    print_status "info" "Adding HTTPS configuration..."
    
    # Append HTTPS configuration to the existing file
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

    # Add HTTPS redirect if enabled
    if [[ "$FORCE_HTTPS" == "yes" ]]; then
        # Add redirect to the HTTP server block
        sed -i '/server_name $DOMAIN_NAME;/a \ \n    # Redirect HTTP to HTTPS\n    return 301 https://$host$request_uri;' "$config_file"
    fi
    
    print_status "success" "HTTPS configuration added successfully"
    
    # Test and reload configuration
    if nginx -t >> "$LOG_FILE" 2>&1; then
        systemctl reload nginx >> "$LOG_FILE" 2>&1
        print_status "success" "NGINX configuration reloaded with HTTPS"
    else
        print_status "error" "HTTPS configuration test failed. Please check the configuration manually."
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

# Function to restart NGINX safely (with fallback)
restart_nginx_safely() {
    print_status "info" "Applying configuration changes..."
    
    # Test configuration first
    if ! nginx -t >> "$LOG_FILE" 2>&1; then
        print_status "error" "Configuration test failed. Cannot restart NGINX."
        return 1
    fi
    
    # Try to restart NGINX
    if systemctl restart nginx >> "$LOG_FILE" 2>&1; then
        print_status "success" "NGINX restarted successfully"
        return 0
    else
        print_status "error" "Failed to restart NGINX. Attempting to revert changes..."
        
        # Remove the problematic configuration
        if [[ -f "/etc/nginx/sites-enabled/$DOMAIN_NAME" ]]; then
            rm -f "/etc/nginx/sites-enabled/$DOMAIN_NAME"
        fi
        
        # Try to restart with clean configuration
        if systemctl restart nginx >> "$LOG_FILE" 2>&1; then
            print_status "warning" "NGINX restarted after removing problematic configuration. Please check your settings."
        else
            print_status "error" "Critical: NGINX failed to restart even after reverting changes. Manual intervention required."
            print_status "info" "Check system status with: systemctl status nginx"
            print_status "info" "Check logs with: journalctl -xe"
        fi
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

# Function to install reverse proxy
install_reverse_proxy() {
    # Show welcome message and warning first
    show_welcome
    
    # Initialize log file
    > "$LOG_FILE"
    log_message "Starting NGINX Reverse Proxy installation"
    
    # Get user input
    get_user_input
    
    # Validate input
    if ! validate_input; then
        print_status "error" "Please fix the errors above and run the script again."
        return 1
    fi
    
    # Check and install dependencies
    if ! check_dependencies; then
        install_dependencies
    fi
    
    # Create NGINX configuration (HTTP only initially)
    create_nginx_config
    
    # Configure firewall
    configure_firewall
    
    # Test configuration
    if ! test_nginx_config; then
        print_status "error" "Configuration test failed. Please check the errors above."
        return 1
    fi
    
    # Restart NGINX safely
    if ! restart_nginx_safely; then
        print_status "error" "Failed to restart NGINX. Please check the system logs."
        return 1
    fi
    
    # Obtain SSL certificate if enabled (this will add HTTPS config later)
    if [[ "$ENABLE_SSL" == "yes" ]]; then
        obtain_ssl_certificate
    fi
    
    # Display summary
    display_summary
    
    log_message "Installation completed successfully"
    return 0
}

# Main execution
main() {
    check_root
    
    while true; do
        show_menu
        
        case $MENU_CHOICE in
            1)
                if install_reverse_proxy; then
                    read -p "Press Enter to continue..."
                else
                    print_status "error" "Installation failed. Check $LOG_FILE for details."
                    read -p "Press Enter to continue..."
                fi
                ;;
            2)
                remove_reverse_proxy
                read -p "Press Enter to continue..."
                ;;
            3)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                print_status "error" "Invalid option. Please try again."
                sleep 2
                ;;
        esac
    done
}

# Handle script interruption
trap 'echo -e "\n${RED}Operation interrupted by user${NC}"; exit 1' INT

# Run main function
main "$@"
