#!/bin/sh
#
# Docker script to configure and start an IPsec VPN server
#
# DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC! THIS IS ONLY MEANT TO BE RUN
# IN A DOCKER CONTAINER!
#
# Copyright (C) 2016-2017 Lin Song <linsongui@gmail.com>
# Based on the work of Thomas Sarlandie (Copyright 2012)
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
# Unported License: http://creativecommons.org/licenses/by-sa/3.0/
#
# Attribution required: please include my name in any derivative and let me
# know how you have improved it!

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exiterr() { echo "Error: $1" >&2; exit 1; }

check_ip() {
  IP_REGEX="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
  printf %s "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

if [ ! -f "/.dockerenv" ]; then
  exiterr "This script ONLY runs in a Docker container."
fi

mkdir -p /opt/src
vpn_env="/opt/src/vpn-gen.env"
if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
  if [ -f "$vpn_env" ]; then
    echo
    echo "Retrieving previously generated VPN credentials..."
    . "$vpn_env"
  else
    echo
    echo "VPN credentials not set by user. Generating random PSK and password..."
    VPN_IPSEC_PSK="$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)"
    VPN_USER=vpnuser
    VPN_PASSWORD="$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)"

    echo "VPN_IPSEC_PSK=$VPN_IPSEC_PSK" > "$vpn_env"
    echo "VPN_USER=$VPN_USER" >> "$vpn_env"
    echo "VPN_PASSWORD=$VPN_PASSWORD" >> "$vpn_env"
    chmod 600 "$vpn_env"
  fi
fi

if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
  exiterr "All VPN credentials must be specified. Edit your 'env' file and re-enter them."
fi

case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD" in
  *[\\\"\']*)
    exiterr "VPN credentials must not contain any of these characters: \\ \" '"
    ;;
esac

echo
echo 'Trying to auto discover IP of this server...'

# In case auto IP discovery fails, manually define the public IP
# of this server in your 'env' file, as variable 'VPN_PUBLIC_IP'.
PUBLIC_IP=${VPN_PUBLIC_IP:-''}

# Try to auto discover IP of this server
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)

# Check IP for correct format
check_ip "$PUBLIC_IP" || PUBLIC_IP=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)
check_ip "$PUBLIC_IP" || exiterr "Cannot find valid public IP. Define it in your 'env' file as 'VPN_PUBLIC_IP'."



# Create IPsec (strongswan) config
cat > /etc/ipsec.conf <<EOF
# ipsec.conf - strongSwan IPsec configuration file
config setup
    uniqueids=never 

conn iOS_cert
    keyexchange=ikev1
    # strongswan version >= 5.0.2, compatible with iOS 6.0,6.0.1
    fragmentation=yes
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    rightcert=client.cert.pem
    auto=add

conn android_xauth_psk
    keyexchange=ikev1
    left=%defaultroute
    leftauth=psk
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=psk
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    auto=add

conn networkmanager-strongswan
    keyexchange=ikev2
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightsourceip=10.31.2.0/24
    rightcert=client.cert.pem
    auto=add

conn windows7
    keyexchange=ikev2
    ike=aes256-sha1-modp1024!
    rekey=no
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=10.31.2.0/24
    rightsendcert=never
    eap_identity=%any
    auto=add

conn win8-win10-ikev2
    keyexchange=ikev2
    leftsendcert=always
    left=%defaultroute
    leftfirewall=yes
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightsourceip=10.31.2.0/24
    auto=add


conn osx10-ios9-ikev2
    keyexchange=ikev2
    left=%defaultroute
    leftfirewall=yes
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    leftsendcert=always
    right=%any
    rightsourceip=10.31.2.0/24
#leftid="xxx.org"
#rightid="*@xxx.org"
    leftid="$PUBLIC_IP"
    rightid="*@$PUBLIC_IP"
    auto=add

conn iOS-IKEV2
    #strictcrlpolicy=no
    auto=add
    dpdaction=clear
    keyexchange=ikev2
    #left
    left=%any
    leftsubnet=0.0.0.0/0
    leftauth=psk
    leftsendcert=always
    leftid=myVPNserver
    #right
    right=%any
    rightsourceip=10.31.2.0/24
    rightauth=eap-mschapv2
    rightid=myVPNclient

include /var/lib/strongswan/ipsec.conf.inc
EOF

# Specify IPsec PSK
cat > /etc/ipsec.secrets <<EOF
# %any  %any  : PSK "$VPN_IPSEC_PSK"

# this file is managed with debconf and will contain the automatically created private key
include /var/lib/strongswan/ipsec.secrets.inc
: RSA server.pem
: PSK "$VPN_IPSEC_PSK"
: XAUTH "$VPN_IPSEC_PSK"
# simon %any : EAP "12345678"
$VPN_USER %any : EAP "$VPN_PASSWORD"

EOF

# Creat strongswan.conf
cat > /etc/strongswan.conf << EOF
# strongswan.conf - strongSwan configuration file
#
# Refer to the strongswan.conf(5) manpage for details
#
# Configuration changes should be made in the included files
charon {
        load_modular = yes
        duplicheck.enable = no
        compress = yes
        plugins {
                include strongswan.d/charon/*.conf
        }
        dns1 = 8.8.8.8
        dns2 = 8.8.4.4
        nbns1 = 8.8.8.8
        nbns2 = 8.8.4.4
}
include strongswan.d/*.conf
EOF

# generate cert

if [ -f "/opt/src/ca.pem" ];then
    echo the ca files already has been created.
else
    ipsec pki --gen --outform pem > ca.pem

    ipsec pki --self --in ca.pem --dn "C=com, O=StrongSwanVPN, CN=StrongSwanVPN CA" \
        --ca --outform pem >ca.cert.pem

    ipsec pki --gen --outform pem > server.pem

    ipsec pki --pub --in server.pem | ipsec pki --issue --cacert ca.cert.pem \
        --cakey ca.pem --dn "C=com, O=StrongSwanVPN, CN=$VPN_PUBLIC_IP" \
        --san="$VPN_PUBLIC_IP" --flag serverAuth --flag ikeIntermediate \
        --outform pem > server.cert.pem

    ipsec pki --gen --outform pem > client.pem

    ipsec pki --pub --in client.pem | ipsec pki --issue --cacert ca.cert.pem \
        --cakey ca.pem --dn "C=com, O=StrongSwanVPN, CN=StrongSwanVPN Client" \
        --san="$VPN_USER@$VPN_PUBLIC_IP"  \
        --outform pem > client.cert.pem

    openssl pkcs12 -export -inkey client.pem -in client.cert.pem \
        -name "client" -certfile ca.cert.pem \
        -caname "StrongSwanVPN CA"  -out client.cert.p12

    openssl base64 -in client.cert.p12 -out client.cert.p12.b64

    openssl x509 -outform der -in ca.cert.pem -out ca.cert.crt

    cp -r ca.cert.pem /etc/ipsec.d/cacerts/
    cp -r server.cert.pem /etc/ipsec.d/certs/
    cp -r server.pem /etc/ipsec.d/private/
    cp -r client.cert.pem /etc/ipsec.d/certs/
    cp -r client.pem  /etc/ipsec.d/private/


# generate mobileconfig file for IOS
    
username="$VPN_USER"
#read -p "Please input userpassword:" password
password="$VPN_PASSWORD"
#read -p "Please input RemoteAddress:" your_server_address
your_server_address="$VPN_PUBLIC_IP"
#read -p "Please input RemoteIdentifier:" leftid
leftid="myVPNserver"
#read -p "Please input LocalIdentifier:" rightid
rightid="myVPNclient"
#read -p "Please input SharedSecret:" your_psk
your_psk="$VPN_IPSEC_PSK"
#read -p "Please input UserDefinedName:" UserDefinedName
UserDefinedName="link-to-DokerVPN"
#read -p "Please input ConfigureDiscriptionName:" PayloadDisplayName
PayloadDisplayName="Docker VPN"
uuid1=`uuidgen`
uuid2=`uuidgen`
uuid3=`uuidgen`
uuid4=`uuidgen`


rm -r -f tmp.mobiconfig

echo   '<?xml version="1.0" encoding="UTF-8"?> '>> tmp.mobiconfig
echo   '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> '>> tmp.mobiconfig
echo   '<plist version="1.0"> '>> tmp.mobiconfig
echo   '<dict> '>> tmp.mobiconfig
echo   '<key>PayloadContent</key> '>> tmp.mobiconfig
echo   '<array> '>> tmp.mobiconfig
echo   '<dict> '>> tmp.mobiconfig
echo   '<key>IKEv2</key> '>> tmp.mobiconfig
echo   '<dict> '>> tmp.mobiconfig
echo   '<key>AuthName</key> '>> tmp.mobiconfig
echo   "<string>"${username}"</string>" >> tmp.mobiconfig
echo   '<key>AuthPassword</key> '>> tmp.mobiconfig
echo   "<string>"${password}"</string> " >> tmp.mobiconfig
echo   '<key>AuthenticationMethod</key> '>> tmp.mobiconfig
echo   '<string>SharedSecret</string> '>> tmp.mobiconfig
echo   '<key>ChildSecurityAssociationParameters</key> '>> tmp.mobiconfig
echo   '<dict> '>> tmp.mobiconfig
echo   '<key>DiffieHellmanGroup</key> '>> tmp.mobiconfig
echo   '<integer>2</integer> '>> tmp.mobiconfig
echo   '<key>EncryptionAlgorithm</key> '>> tmp.mobiconfig
echo   '<string>3DES</string> '>> tmp.mobiconfig
echo   '<key>IntegrityAlgorithm</key> '>> tmp.mobiconfig
echo   '<string>SHA1-96</string> '>> tmp.mobiconfig
echo   '<key>LifeTimeInMinutes</key> '>> tmp.mobiconfig
echo   '<integer>1440</integer> '>> tmp.mobiconfig
echo   '</dict> '>> tmp.mobiconfig
echo   '<key>DeadPeerDetectionRate</key> '>> tmp.mobiconfig
echo   '<string>Medium</string> '>> tmp.mobiconfig
echo   '<key>DisableMOBIKE</key> '>> tmp.mobiconfig
echo   '<integer>0</integer> '>> tmp.mobiconfig
echo   '<key>DisableRedirect</key> '>> tmp.mobiconfig
echo   '<integer>0</integer> '>> tmp.mobiconfig
echo   '<key>EnableCertificateRevocationCheck</key> '>> tmp.mobiconfig
echo   '<integer>0</integer> '>> tmp.mobiconfig
echo   '<key>EnablePFS</key> '>> tmp.mobiconfig
echo   '<integer>0</integer> '>> tmp.mobiconfig
echo   '<key>ExtendedAuthEnabled</key> '>> tmp.mobiconfig
echo   '<true/> '>> tmp.mobiconfig
echo   '<key>IKESecurityAssociationParameters</key> '>> tmp.mobiconfig
echo   '<dict> '>> tmp.mobiconfig
echo   '<key>DiffieHellmanGroup</key> '>> tmp.mobiconfig
echo   '<integer>2</integer> '>> tmp.mobiconfig
echo   '<key>EncryptionAlgorithm</key> '>> tmp.mobiconfig
echo   '<string>3DES</string> '>> tmp.mobiconfig
echo   '<key>IntegrityAlgorithm</key> '>> tmp.mobiconfig
echo   '<string>SHA1-96</string> '>> tmp.mobiconfig
echo   '<key>LifeTimeInMinutes</key> '>> tmp.mobiconfig
echo   '<integer>1440</integer> '>> tmp.mobiconfig
echo   '</dict> '>> tmp.mobiconfig
echo   '<key>LocalIdentifier</key> '>> tmp.mobiconfig
echo   "<string>"${rightid}"</string> " >> tmp.mobiconfig
echo   '<key>RemoteAddress</key> '>> tmp.mobiconfig
echo   "<string>"${your_server_address}"</string> " >> tmp.mobiconfig
echo   '<key>RemoteIdentifier</key> '>> tmp.mobiconfig
echo   "<string>"${leftid}"</string> " >> tmp.mobiconfig
echo   '<key>SharedSecret</key> '>> tmp.mobiconfig
echo   "<string>"${your_psk}"</string> " >> tmp.mobiconfig
echo   '<key>UseConfigurationAttributeInternalIPSubnet</key> '>> tmp.mobiconfig
echo   '<integer>0</integer> '>> tmp.mobiconfig
echo   '</dict> '>> tmp.mobiconfig
echo   '<key>IPv4</key> '>> tmp.mobiconfig
echo   '<dict> '>> tmp.mobiconfig
echo   '<key>OverridePrimary</key> '>> tmp.mobiconfig
echo   '<integer>1</integer> '>> tmp.mobiconfig
echo   '</dict> '>> tmp.mobiconfig
echo   '<key>PayloadDescription</key> '>> tmp.mobiconfig
echo   '<string>Configures VPN settings</string> '>> tmp.mobiconfig
echo   '<key>PayloadDisplayName</key> '>> tmp.mobiconfig
echo   '<string>VPN</string> '>> tmp.mobiconfig
echo   '<key>PayloadIdentifier</key> '>> tmp.mobiconfig
echo   "<string>com.apple.vpn.managed."${uuid1}"</string> ">> tmp.mobiconfig
echo   '<key>PayloadType</key> '>> tmp.mobiconfig
echo   '<string>com.apple.vpn.managed</string> '>> tmp.mobiconfig
echo   '<key>PayloadUUID</key> '>> tmp.mobiconfig
echo   "<string>"${uuid2}"</string> ">> tmp.mobiconfig
echo   '<key>PayloadVersion</key> '>> tmp.mobiconfig
echo   '<real>1</real> '>> tmp.mobiconfig
echo   '<key>Proxies</key> '>> tmp.mobiconfig
echo   '<dict> '>> tmp.mobiconfig
echo   '<key>HTTPEnable</key> '>> tmp.mobiconfig
echo   '<integer>0</integer> '>> tmp.mobiconfig
echo   '<key>HTTPSEnable</key> '>> tmp.mobiconfig
echo   '<integer>0</integer> '>> tmp.mobiconfig
echo   '</dict> '>> tmp.mobiconfig
echo   '<key>UserDefinedName</key> '>> tmp.mobiconfig
echo   "<string>"${UserDefinedName}"</string> " >> tmp.mobiconfig
echo   '<key>VPNType</key> '>> tmp.mobiconfig
echo   '<string>IKEv2</string> '>> tmp.mobiconfig
echo   '<key>VendorConfig</key> '>> tmp.mobiconfig
echo   '<dict/> '>> tmp.mobiconfig
echo   '</dict> '>> tmp.mobiconfig
echo   '</array> '>> tmp.mobiconfig
echo   '<key>PayloadDisplayName</key> '>> tmp.mobiconfig
echo   "<string>"${PayloadDisplayName}"</string> ">> tmp.mobiconfig
echo   '<key>PayloadIdentifier</key> '>> tmp.mobiconfig
echo   "<string>"${uuid3}"</string> ">> tmp.mobiconfig
echo   '<key>PayloadRemovalDisallowed</key> '>> tmp.mobiconfig
echo   '<false/> '>> tmp.mobiconfig
echo   '<key>PayloadType</key> '>> tmp.mobiconfig
echo   '<string>Configuration</string> '>> tmp.mobiconfig
echo   '<key>PayloadUUID</key> '>> tmp.mobiconfig
echo   "<string>"${uuid4}"</string> ">> tmp.mobiconfig
echo   '<key>PayloadVersion</key> '>> tmp.mobiconfig
echo   '<integer>1</integer> '>> tmp.mobiconfig
echo   '</dict> '>> tmp.mobiconfig
echo   '</plist> '>> tmp.mobiconfig

mv tmp.mobiconfig $VPN_USER.mobileconfig

cp $VPN_USER.mobileconfig /data

# echo  "Sending config file to client mailbox ...."

# echo "This is the iOS moblie configure file." | mutt -s "Mobile config of arctg" simon-zhou@outlook.com -a /root/arctg.mobileconfig

# echo "OK!"
fi

# Update sysctl settings
SYST='/sbin/sysctl -e -q -w'
$SYST kernel.msgmnb=65536
$SYST kernel.msgmax=65536
$SYST kernel.shmmax=68719476736
$SYST kernel.shmall=4294967296
$SYST net.ipv4.ip_forward=1
$SYST net.ipv4.tcp_syncookies=1
$SYST net.ipv4.conf.all.accept_source_route=0
$SYST net.ipv4.conf.default.accept_source_route=0
$SYST net.ipv4.conf.all.accept_redirects=0
$SYST net.ipv4.conf.default.accept_redirects=0
$SYST net.ipv4.conf.all.send_redirects=0
$SYST net.ipv4.conf.default.send_redirects=0
$SYST net.ipv4.conf.lo.send_redirects=0
$SYST net.ipv4.conf.eth0.send_redirects=0
$SYST net.ipv4.conf.all.rp_filter=0
$SYST net.ipv4.conf.default.rp_filter=0
$SYST net.ipv4.conf.lo.rp_filter=0
$SYST net.ipv4.conf.eth0.rp_filter=0
$SYST net.ipv4.icmp_echo_ignore_broadcasts=1
$SYST net.ipv4.icmp_ignore_bogus_error_responses=1
$SYST net.core.wmem_max=12582912
$SYST net.core.rmem_max=12582912
$SYST net.ipv4.tcp_rmem="10240 87380 12582912"
$SYST net.ipv4.tcp_wmem="10240 87380 12582912"

# Create IPTables rules
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
iptables -A FORWARD -s 10.31.2.0/24  -j ACCEPT
iptables -A INPUT -i eth0 -p esp -j ACCEPT
iptables -A INPUT -i eth0 -p udp --dport 500 -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 500 -j ACCEPT
iptables -A INPUT -i eth0 -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -i eth0 -p udp --dport 1701 -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --dport 1723 -j ACCEPT
iptables -A FORWARD -j REJECT
iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o eth0 -j MASQUERADE


# Update file attributes
chmod 600 /etc/ipsec.secrets 

cat <<EOF

================================================

IPsec VPN server is now ready for use!

Connect to your new VPN with these details:

Server IP: $PUBLIC_IP
IPsec PSK: $VPN_IPSEC_PSK
Username: $VPN_USER
Password: $VPN_PASSWORD

Write these down. You'll need them to connect!

Important notes:   https://git.io/vpnnotes2
Setup VPN clients: https://git.io/vpnclients

================================================

EOF

# Load IPsec NETKEY kernel module
modprobe af_key

# Start services

ipsec start --config /etc/ipsec.conf

