#!/bin/bash

# This script contains functions for installing and NGINX web server for serving satic files using ssl and basic authentication

# USER DEFINED VARIABLES

## Self-Signed Certificate info
DURATION_DAYS=3650
ARTIFACT_COMMON_NAME=artifacts.local.edge
COUNTRY=US
STATE=MA
LOCATION=LAB
ORGANIZATION=SELF

## Basic Authentication info
HTUSER=edgeuser
HTPASS=NativeEdge123!

## SSL Port and Server titles
NGINX_PORT=443
BROWSER_TITLE="Artifact Server"
BODY_TITLE="Artifact Server"

## Scirpt Execution options
INSTALL_SERVER=true
UPDATE_SERVER=false
DELETE_SERVER=false
OFFLINE_PREP=false
DEBUG=false

## Update Params
ADD_OR_UPDATE_USER=false
UPDATE_SSL=false
GEN_NEW_CERT=true
UPDATE_CERT_PATH=""
UPDATE_CERT_KEY_PATH=""

## Delete Params
DELETE_DATA=true

# Global variables (Do not edit)
WORKING_DIR=$(pwd)
mgmt_ip=$(hostname -I | awk '{print $1}')
current_hostname=$(hostname)
ubuntu_release=$(lsb_release -r | awk '{print $2}')
CERT_CRT_NAME=$ARTIFACT_COMMON_NAME.crt
CERT_KEY_NAME=$ARTIFACT_COMMON_NAME.key
CERT_KEY_PATH=/etc/nginx/certs/artifacts/$CERT_KEY_NAME
CERT_CRT_PATH=/etc/nginx/certs/artifacts/$CERT_CRT_NAME


### Functions

# Debug output, example 'debug_run <command or function>'
function debug_run() {
  # Check the value of the global DEBUG variable
  if [ "$DEBUG" = "true" ]; then
    # If DEBUG is true, execute the command/function normally.
    # All stdout and stderr will be displayed to the console.
    echo "--- DEBUG: Running '$*' ---"
    "$@"
    local status=$? # Capture the exit status of the executed command
    echo "--- DEBUG: Finished '$*' with status $status ---"
    return $status # Return the original command's exit status
  else
    echo "Suppressing debug output for '$*'..."
    # If DEBUG is false, execute the command/function and redirect
    # all standard output (1) and standard error (2) to /dev/null.
    # This effectively suppresses all output.
    "$@" > /dev/null 2>&1
    return $? # Return the original command's exit status
  fi
}

function install_server () {
    offline_prep
    create_local_repo
    prepare_dirs
    debug_run install_prerequisites
    cert_gen
    auth_gen
    conf_gen
    apply_server
    gen_curl_params
    restore_apt_repos
    cleanup_install
}

function offline_prep () {
    if [[ $OFFLINE_PREP == "true" && ! -f $WORKING_DIR/nginx/packages/Packages ]]; then
      echo "Offline install detected, installing dkpg-dev and downloading packages for nginx and apache2-utils"
      debug_run install_dpkg_dev
      debug_run apt_download_packs
      echo "Offline packages prepared.."
      echo "Run ./install_nginx.sh again to install with local repository, or copy nginx_offline_install.tar.gz to the target server for offline execution."
      exit
    fi
}

function install_dpkg_dev () {
      if ! command -v dpkg-scanpackages &> /dev/null; then
      sudo apt update
      DEBIAN_FRONTEND=noninteractive sudo apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install dpkg-dev
      #DEBIAN_FRONTEND=noninteractive sudo apt-get install -y dpkg-dev
      fi
}

function apt_download_packs () {
      local PACKAGES="nginx apache2-utils"
      echo "Downloading offline packages for future use..."
      mkdir -p $WORKING_DIR/nginx/packages
      cd $WORKING_DIR/nginx/packages
      sudo apt-get download $(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances --no-pre-depends ${PACKAGES} | grep "^\w")
      dpkg-scanpackages -m . > Packages
      cd $WORKING_DIR
      curl https://ssl-config.mozilla.org/ffdhe2048.txt > $WORKING_DIR/nginx/dhparam
      tar czvf nginx_offline_install-Ubuntu-$ubuntu_release.tar.gz -C ./nginx install_nginx.sh
}

function create_local_repo () {
    if [[ $OFFLINE_PREP == "true" && -f $WORKING_DIR/nginx/packages/Packages ]]; then
      echo "Offline install detected, creating local repo from packages"
      if [[ $ubuntu_release == "22.04" ]]; then
        sudo mv /etc/apt/sources.list /etc/apt/sources.list.backup
      elif [[ $ubuntu_release == "24.04" ]]; then
        sudo mv /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.list.backup
      fi
      echo "deb [trusted=yes] file:$WORKING_DIR/nginx/packages ./" | sudo tee -a /etc/apt/sources.list.d/nginx.list
    fi
}

function prepare_dirs () {
    echo "Preparing directory structure..."
    if [ ! -d $WORKING_DIR/nginx/certs ]; then
      mkdir -p $WORKING_DIR/nginx/certs
    fi
    if [ ! -d /var/www/nginx/artifacts ]; then
      sudo mkdir -p /var/www/nginx/artifacts
      sudo chown -R www-data:www-data /var/www/nginx
    fi
    if [ ! -d /etc/nginx/auth/artifacts ]; then
      sudo mkdir -p /etc/nginx/auth/artifacts
    fi
    if [ ! -d /etc/nginx/certs/artifacts ]; then
      sudo mkdir -p /etc/nginx/certs/artifacts
    fi
}

function install_prerequisites () {
    echo "Installing NGINX and Apache2-utils packages..."
    sudo apt update
    if ! command -v nginx &> /dev/null; then
        DEBIAN_FRONTEND=noninteractive sudo apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install nginx
        #DEBIAN_FRONTEND=noninteractive sudo apt-get -y install nginx
    else
        echo "NGINX is already installed!"
    fi
    if ! command -v htpasswd &> /dev/null; then
        echo "Installing htpasswd..."
        DEBIAN_FRONTEND=noninteractive sudo apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install apache2-utils
        #DEBIAN_FRONTEND=noninteractive sudo apt-get -y install apache2-utils
    else
        echo "htpasswd is already installed!"
    fi
    sudo rm -f /etc/nginx/sites-enabled/*
    if [ -f $WORKING_DIR/nginx/dhparam ]; then
        echo "dhparam already exists"
    else
        curl https://ssl-config.mozilla.org/ffdhe2048.txt > $WORKING_DIR/nginx/dhparam
    fi
    echo "Done with prerequisite packages..."
}

# Create self-signed certificates
function cert_gen () {
  echo "Creating self-signed certificate valid for $DURATION_DAYS days..."
  # Generate CA key
  openssl genrsa -out $WORKING_DIR/nginx/certs/ca.key 4096
  # Generate CA certificate
  openssl req -x509 -new -nodes -sha512 -days $DURATION_DAYS -subj "/C=$COUNTRY/ST=$STATE/L=$LOCATION/O=$ORGANIZATION/CN=$ARTIFACT_COMMON_NAME" -key $WORKING_DIR/nginx/certs/ca.key -out $WORKING_DIR/nginx/certs/ca.crt
  # Generate server key
  openssl genrsa -out $WORKING_DIR/nginx/certs/$ARTIFACT_COMMON_NAME.key 4096
  # Generate server CSR
  openssl req -sha512 -new -subj "/C=$COUNTRY/ST=$STATE/L=$LOCATION/O=$ORGANIZATION/CN=$ARTIFACT_COMMON_NAME" -key $WORKING_DIR/nginx/certs/$ARTIFACT_COMMON_NAME.key -out $WORKING_DIR/nginx/certs/$ARTIFACT_COMMON_NAME.csr
  # Create v3 extension
  cat > $WORKING_DIR/nginx/certs/v3.ext <<-EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1=$mgmt_ip
DNS.1=$ARTIFACT_COMMON_NAME
DNS.2=$current_hostname
EOF

  # Generate signed certificate
  openssl x509 -req -sha512 -days $DURATION_DAYS -extfile $WORKING_DIR/nginx/certs/v3.ext -CA $WORKING_DIR/nginx/certs/ca.crt -CAkey $WORKING_DIR/nginx/certs/ca.key -CAcreateserial -in $WORKING_DIR/nginx/certs/$ARTIFACT_COMMON_NAME.csr -out $WORKING_DIR/nginx/certs/$ARTIFACT_COMMON_NAME.crt
echo "Certificat generation completed..."
}

# create htpasswd file for basic auth
function auth_gen () {
    if [[ $ADD_OR_UPDATE_USER == "true" && $UPDATE_SERVER == "true" ]]; then
        echo "Adding or updating user $HTUSER with password $HTPASS"
        sudo htpasswd -b /etc/nginx/auth/artifacts/htpasswd "$HTUSER" "$HTPASS"
      return
    elif [[ $INSTALL_SERVER == "true" ]]; then
      echo "Creating new authentication file with user $HTUSER with password $HTPASS."
      sudo htpasswd -bc "/etc/nginx/auth/artifacts/htpasswd" "$HTUSER" "$HTPASS"
    fi
}

function conf_gen () {
    echo "Creating NGINX configuration file..."
    cat > $WORKING_DIR/nginx/$ARTIFACT_COMMON_NAME.conf <<EOF
# HTTP server block for redirection to HTTPS on port 4443
# Some parameters based on Mozzilla SSL config https://ssl-config.mozilla.org/#server=nginx&version=1.27.3&config=intermediate&openssl=3.4.0&ocsp=false&guideline=5.7
server {
    listen 80;
    listen [::]:80;
    server_name _; # Catches all hostnames

    # Redirect all HTTP traffic to HTTPS on port 4443
    # \$host includes the domain name, \$request_uri is the full path and query string
    return 301 https://\$host:$NGINX_PORT\$request_uri;
}

# HTTPS server block for serving content on port 4443
server {
    listen $NGINX_PORT ssl http2; # Added http2 for performance
    listen [::]:$NGINX_PORT ssl http2;

    server_name _; # Catches all hostnames for this port

    ssl_certificate $CERT_CRT_PATH;
    ssl_certificate_key $CERT_KEY_PATH;

    # Intermediate SSL configuration - good choices here!
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    # Note: ssl_prefer_server_ciphers off is generally fine with modern cipher lists.
    # If you want to strictly control cipher order, set it to 'on'.
    ssl_prefer_server_ciphers off;

    # SSL Session Management
    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m; # about 40000 sessions

    # Diffie-Hellman parameters (ensure this file exists and is strong)
    ssl_dhparam "/etc/nginx/dhparam";

    # HSTS (Highly Recommended for HTTPS-only sites)
    # Add this if you are confident your SSL setup is stable and persistent.
    # It forces browsers to always use HTTPS for your domain for a specified duration.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    # Uncomment the above line after testing your HTTPS setup thoroughly.

    # Root directory for your webserver
    root /var/www/nginx;
    index index.html;

    # Location for the homepage and general static files
    location / {
        try_files \$uri \$uri/ =404;
        # Basic authentication (comment out if not required)
        auth_basic "Login Required";
        auth_basic_user_file /etc/nginx/auth/artifacts/htpasswd;
    }

    # Location for the /artifacts directory with autoindexing
    location /artifacts {
        autoindex on; # Enables directory listing
        try_files \$uri \$uri/ =404;
        # Basic authentication (comment out if not required)
        auth_basic "Login Required";
        auth_basic_user_file /etc/nginx/auth/artifacts/htpasswd;
    }
}
EOF

    echo "Creating index.html files..."
    cat > $WORKING_DIR/nginx/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>$BROWSER_TITLE</title>
    <style>
        body {
            text-align: center;
            font-family: Arial, sans-serif;
        }
        .title {
            font-size: 48px;
            color: blue;
            margin-bottom: 10px;
        }
        .subtitle {
            font-size: 32px;
            color: black;
        }
        .note {
            font-size: 16px;
            color: black;
        }

        .link {
            font-size: 32px;
            display: block;
            margin: 20px 0;
        }
        table {
            width: 80%;
            margin: 0 auto;
            border-collapse: collapse;
        }
        th, td {
            border: 1px solid #333;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        caption {
            font-size: 1.5em;
            margin: 20px 0 10px;
        }
    </style>
</head>
<body>
    <p class="title">$BODY_TITLE</p>
    <p class="note">Powered by NGINX</p>
    <p class="subtitle">Static Files found here:</p>
    <a class="link" href="/artifacts" title="Artifacts" rel="nofollow">Artifacts</a>
    <p class="note">Files are stored in the /var/www/nginx/artifacts directory of this server</p>
</body>
</html>
EOF
}

# Test server and apply
function apply_server () {
    echo "Applying server config..."
    if [ ! -d /etc/nginx/certs/artifacts ]; then
      sudo mkdir -p /etc/nginx/certs/artifacts
    fi
    if [[ -d $WORKING_DIR/nginx/certs ]]; then
      sudo cp $WORKING_DIR/nginx/certs/$CERT_KEY_NAME $CERT_KEY_PATH
      sudo cp $WORKING_DIR/nginx/certs/$CERT_CRT_NAME $CERT_CRT_PATH
    fi
    if [ -f $WORKING_DIR/nginx/dhparam ]; then 
      sudo cp $WORKING_DIR/nginx/dhparam /etc/nginx/dhparam
    fi
    sudo cp $WORKING_DIR/nginx/index.html /var/www/nginx/
    sudo cp $WORKING_DIR/nginx/$ARTIFACT_COMMON_NAME.conf /etc/nginx/sites-available/$ARTIFACT_COMMON_NAME.conf
    sudo ln -s /etc/nginx/sites-available/$ARTIFACT_COMMON_NAME.conf /etc/nginx/sites-enabled/
    echo "Verifying configuration and reloading NGINX..."
    sudo systemctl enable nginx
    sudo systemctl start nginx
    sudo nginx -t
    sudo systemctl restart nginx
}

function gen_curl_params () {
  base64_auth_string=$(echo -n "$HTUSER:$HTPASS" | base64)
  curl_header="\"Authorization: Basic $base64_auth_string\""
  curl_config=$(echo "--user $HTUSER:$HTPASS --insecure")
}

function restore_apt_repos () {
    if [[ $OFFLINE_PREP == "true" ]]; then
      if [[ $ubuntu_release == "22.04" ]]; then
        sudo mv /etc/apt/sources.list.backup /etc/apt/sources.list
      elif [[ $ubuntu_release == "24.04" ]]; then
        sudo mv /etc/apt/sources.list.d/ubuntu.list.backup /etc/apt/sources.list.d/ubuntu.sources
      fi
    fi
}

function cleanup_install () {
    echo "Cleaning up..."
    if [ -d $WORKING_DIR/nginx ]; then
      sudo rm -rf $WORKING_DIR/nginx
    fi
    if [[ -f /etc/apt/sources.list.d/nginx.list ]]; then
      sudo rm /etc/apt/sources.list.d/nginx.list
    fi
}

function update_server () {
  prepare_dirs
  auth_gen
  if [[ $UPDATE_SSL == "true" && $GEN_NEW_CERT == "true" ]]; then
    echo "GEN_NEW_CERT=$GEN_NEW_CERT, creating new SSL certificates..."
    sudo rm -rf /etc/nginx/certs/artifacts/*
    cert_gen
  elif [[ $UPDATE_SSL == "true" && $GEN_NEW_CERT == "false" ]]; then
    echo "GEN_NEW_CERT=$GEN_NEW_CERT, updating SSL with custom certificates..."
    if [[ ! -f $UPDATE_CERT_KEY_PATH  || ! -f $UPDATE_CERT_PATH ]]; then 
      echo "ERROR: For custom certificates, you must specify a valid file path for both the key and certificate."
      exit 1
    fi
    sudo rm -f /etc/nginx/certs/artifacts/*
    sudo cp $UPDATE_CERT_KEY_PATH $WORKING_DIR/nginx/certs/
    sudo cp $UPDATE_CERT_PATH $WORKING_DIR/nginx/certs/
    CERT_CRT_NAME=$(basename $UPDATE_CERT_PATH)
    CERT_KEY_NAME=$(basename $UPDATE_CERT_KEY_PATH)
    CERT_KEY_PATH=/etc/nginx/certs/artifacts/$CERT_KEY_NAME
    CERT_CRT_PATH=/etc/nginx/certs/artifacts/$CERT_CRT_NAME
  fi
  sudo rm -f /var/www/nginx/index.html
  sudo rm -f /etc/nginx/sites-enabled/*.conf
  sudo rm -f /etc/nginx/sites-available/*.conf
  conf_gen
  apply_server
  gen_curl_params
  cleanup_install
}

function delete_server () {
    if [[ $DELETE_SERVER == "true" ]]; then
    echo "Deleting NGINX Artifact server with DEBUG=$DEBUG and DELETE_DATA=$DELETE_DATA"
    debug_run delete_env
    echo "NGINX Artifact server delete workflow completed."
    fi
}

function delete_env () {
    sudo systemctl stop nginx
    sudo systemctl disable nginx
    sudo rm -rf /etc/nginx/certs
    sudo rm -rf /etc/nginx/auth
    sudo rm -rf /etc/nginx/sites-available/*
    sudo rm -rf /etc/nginx/sites-enabled/*
    sudo rm -rf /etc/nginx/dhparam
    if [[ $DELETE_DATA == "true" ]]; then
      sudo rm -rf /var/www/nginx
    fi
    cleanup_install
}

# Script Execution
if [[ $INSTALL_SERVER == "true" && $UPDATE_SERVER == "true" && $DELETE_SERVER == "true" ]]; then
    echo "Only one of INSTALL_SERVER, UPDATE_SERVER, or DELETE_SERVER can be set to true at a time. Exiting..."
    exit 0
elif [[ $INSTALL_SERVER == "true" && $UPDATE_SERVER = "false" && $DELETE_SERVER = "false" ]]; then
    echo "Installing NGINX Artifact server with DEBUG=$DEBUG and OFFLINE_PREP=$OFFLINE_PREP"
    install_server
    echo "NGINX Artifact server install workflow completed."
    echo "CURL config string is '$curl_config'"
    echo "CURL header is $curl_header"
    echo "Artifact server is available at https://$mgmt_ip:$NGINX_PORT"
elif [[ $UPDATE_SERVER == "true" && $INSTALL_SERVER == "false" && $DELETE_SERVER == "false" ]]; then
    echo "Updating NGINX Artifact server config."
    echo "ADD_OR_UPDATE_USER=$ADD_OR_UPDATE_USER, UPDATE_SSL=$UPDATE_SSL"
    update_server
    echo "NGINX Artifact server update workflow completed."
    echo "Updated/New User CURL config string is '$curl_config'"
    echo "Updated/Ner User CURL header is $curl_header"
    echo "Artifact server is available at https://$mgmt_ip:$NGINX_PORT"
elif [[ $DELETE_SERVER == "true" && $INSTALL_SERVER == "false" && $UPDATE_SERVER == "false" ]]; then
    delete_server
else
    echo "Only one of INSTALL_SERVER, UPDATE_SERVER, or DELETE_SERVER can be set to true at a time."
    echo "Update variables in install_nginx.sh and try again..."
fi
