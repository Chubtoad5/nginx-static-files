# Simple NGINX Static File Server

## Info
- Installs NGINX and appache2-utils
- sets up NGINX to serve static files over tcp port of user's choosing
- leverages most SSL best practices for secure connections
- leverages basic authentication

## Instructions
- Intended only for Ubuntu 22.04 and 24.04 operating system
- clone the repo or download the install_nginx.sh script
- chmod +x install_nginx.sh
- Edit the install_nginx.sh, change the variables from USER DEFINED VARIABLES section match your needs
- Run the script (may prompt user to authenticate sudo user) "$ ./install_nginx.sh"
- Script output will provide web server details including URL and authentication strings