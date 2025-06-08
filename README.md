# Simple NGINX Static File Server

## Info
- Installs NGINX and appache2-utils
- sets up NGINX to serve static files over tcp port of user's choosing
- leverages most SSL best practices for secure connections
- leverages basic authentication
- supports generating offline package for non-internet connected hosts
- supports updating the server
- supports deleting the server

## Deb packages installed
- dpkg-dev and all required dependencies
- nginx and all required dependencies
- apache2-utils and all required dependencies

## Instructions
- Intended only for Ubuntu 22.04 and 24.04 operating system
- clone the repo or download the install_nginx.sh script
- chmod +x install_nginx.sh
- Edit the install_nginx.sh, change the variables from USER DEFINED VARIABLES section match your needs
- Run the script (may prompt user to authenticate sudo user) "$ ./install_nginx.sh"
- Script output will provide web server details including URL and authentication strings

## VARIABLES

### SSL Certificate info
DURATION_DAYS=3650
ARTIFACT_COMMON_NAME=artifacts.local.edge
COUNTRY=US
STATE=MA
LOCATION=LAB
ORGANIZATION=SELF

### Basic Authentication info
HTUSER=edgeuser
HTPASS=NativeEdge123!
NGINX_PORT=443
BROWSER_TITLE="Artifact Server"
BODY_TITLE="Artifact Server"

### Scirpt Execution options
INSTALL_SERVER=true
UPDATE_SERVER=false
DELETE_SERVER=false
OFFLINE_PREP=false
DEBUG=false

### Update Params
UPDATE_USER=true
ADD_HTUSER=false
UPDATE_HTPASS=admin
UPDATE_HTUSER=admin
UPDATE_SSL=false
UPDATE_TCP_PORT=""
GEN_NEW_CERT=true
UPDATE_CERT_PATH=""
UPDATE_CERT_KEY_PATH=""
UPDATE_HEAD=""
UPDATE_BODY=""

### Delete Params
DELETE_DATA=true

## Author Notes

This is an opensource tools for installing a basic static file server.