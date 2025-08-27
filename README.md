# Nginx Proxy Auto Install

A user-friendly bash script that automates setting up Nginx reverse proxy configurations. Because life's too short to manually edit config files.

## What Problem Does This Solve?

If you've ever deployed an application (Node.js, Python, React, etc.) that runs on a specific port (like 3000, 8000, or 8080), you know the struggle: people can't access it directly by port number, and setting up proper domain routing with SSL is a pain.

This script handles the boring parts for you. It creates the bridge between your domain name and your application, with optional HTTPS encryption - because nobody likes angry browser security warnings.

## Key Features

- **Simple Menu Interface**: No memorizing complex commands or flags  
- **Input Validation**: It catches typos and silly mistakes so you don't have to  
- **SSL/TLS Setup**: Automatic Let's Encrypt certificate configuration  
- **WebSocket Support**: For real-time applications  
- **Security Headers**: Basic protection against common vulnerabilities  
- **Firewall Configuration**: Automatically opens necessary ports  
- **Clean Removal**: Easily undo what you've created  

## Installation & Usage

```bash
bash <(curl -s https://proxy.thedevjo.com)
```
Yes, it's that simple. The script will guide you through the rest.
Prerequisites

Before you begin, make sure you:

  - Have a server (VPS, cloud instance, etc.)

  - Own a domain name

  - Have created an A record pointing your domain to your server's IP

  - Have sudo privileges on the server

**Pro tip**: DNS changes can take time to propagate. Set up your domain records at least a few hours before running this script to avoid SSL certificate issues.
## How It Works

  - Run the installation command above

  - Answer the simple questions (backend IP/port, domain name, etc.)

  - Let the script handle the Nginx configuration, SSL setup, and firewall rules

  - Test your new professionally-proxied application

## Managing Configurations

Changed your mind? Need to remove a proxy configuration? Just run the script again and select option 2 from the menu. It will show you all active configurations and let you clean up what you don't need.
Troubleshooting

If something goes wrong (because computers sometimes enjoy being difficult), check the log file:
/var/log/nginx-reverse-proxy-installer.log feel free to create an issue on this github repo, happy to assist.

**Important Note:**

This script is provided as-is. While it's been tested and should work smoothly, always understand what a script does before running it on your server. With great power comes great responsibility, and all that
