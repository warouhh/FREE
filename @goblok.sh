#!/bin/bash
MYIP=$(curl -sS ipv4.icanhazip.com)
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
NC='\e[0m'
hosting=$(curl -sS https://raw.githubusercontent.com/Azigaming404/Autoscript-by-azi/main/domain)
# Getting
MYIP=$(wget -qO- ipinfo.io/ip);
echo "memeriksa vps anda"
sleep 0.5
CEKEXPIRED () {
        today=$(date -d +1day +%Y -%m -%d)
        Exp1=$(curl -sS https://$hosting/Autoscript-by-azi-main/izin | grep $MYIP | awk '{print $3}')
        if [[ $today < $Exp1 ]]; then
        echo "status script aktif.."
        else
        echo "SCRIPT ANDA EXPIRED";
        exit 0
fi
}
IZIN=$(curl -sS https://$hosting/Autoscript-by-azi-main/izin | awk '{print $4}' | grep $MYIP)
if [ $MYIP = $IZIN ]; then
echo "IZIN DI TERIMA!!"
else
echo "Akses di tolak!! Benget sia hurung!!";
exit 0
fi
sudo apt install -y python3 python3-pip
pip3 install pyarmor

localip=$(hostname -I | cut -d\  -f1)
hst=( `hostname` )
dart=$(cat /etc/hosts | grep -w `hostname` | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
echo "$localip $(hostname)" >> /etc/hosts
fi
if [ -f "/root/log-install.txt" ]; then
rm -fr /root/log-install.txt
fi
mkdir -p /etc/xray
mkdir -p /etc/v2ray
touch /etc/xray/domain
touch /etc/v2ray/domain
touch /etc/xray/scdomain
touch /etc/v2ray/scdomain

curl ipinfo.io/org > /etc/org
curl ipinfo.io/city > /etc/city
curl ipinfo.io/ip > /etc/ip


ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

apt install git curl -y >/dev/null 2>&1
apt install python -y >/dev/null 2>&1
echo -e "[ ${green}INFO${NC} ] Aight good ... installation file is ready"
sleep 2

mkdir -p /var/lib/scrz-prem >/dev/null 2>&1
echo "IP=" >> /var/lib/scrz-prem/ipvps.conf

sudo apt install vnstat
sudo apt insta squid
wget -q -O https://raw.githubusercontent.com/Azigaming404/Autoscript-by-azi/main/tools.sh && chmod +x tools.sh && ./tools.sh
rm tools.sh
clear
sleep 1
echo "Pilih opsi domain:"
echo "1. Domain custom"
echo "2. Domain otomatis"

read -p "Masukkan pilihan (1 atau 2): " choice

if [ "$choice" == "1" ]; then
clear
echo "Add Domain for vmess/vless/trojan dll"
echo " "
read -rp "Input ur domain : " -e pp
    if [ -z $pp ]; then
        echo -e "
        Nothing input for domain!
        Then a random domain will be created"
    else
        echo "$pp" > /root/scdomain
	echo "$pp" > /etc/xray/scdomain
	echo "$pp" > /etc/xray/domain
	echo "$pp" > /etc/v2ray/domain
	echo $pp > /root/domain
        echo "IP=$pp" > /var/lib/scrz-prem/ipvps.conf
    fi


elif [ "$choice" == "2" ]; then
    echo "Anda memilih domain otomatis."


# Get public IP address
MYIP=$(wget -qO- ipinfo.io/ip)
clear

# Install required software
apt install jq curl -y

# Generate a random subdomain
sub=$(</dev/urandom tr -dc a-z | head -c4)
DOMAIN=virtualtunneling.tech
SUB_DOMAIN=${sub}.virtualtunneling.tech
CF_ID=vpncyber673@gmail.com
CF_KEY=2186e4da5f4515ed99965317d4ca388bba2ce
set -euo pipefail
IP=$(curl -sS ifconfig.me)

# Update DNS for SUB_DOMAIN
echo "Updating DNS for ${SUB_DOMAIN}..."
ZONE=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN}&status=active" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

RECORD_A=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?name=${SUB_DOMAIN}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

if [[ "${#RECORD_A}" -le 10 ]]; then
     RECORD_A=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"A","name":"'${SUB_DOMAIN}'","content":"'${IP}'","ttl":120,"proxied":false}' | jq -r .result.id)
fi

echo $SUB_DOMAIN > /root/domain
echo "IP=$SUB_DOMAIN" > /var/lib/scrz-prem/ipvps.conf
sleep 1
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "Domain added.."
sleep 3
domain=$(cat /root/domain)
cp -r /root/domain /etc/xray/domain
domain2=ns.$domain

# Add NS record
RECORD_NS=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records?type=NS&name=${DOMAIN}" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

if [[ "${#RECORD_NS}" -le 10 ]]; then
     RECORD_NS=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records" \
     -H "X-Auth-Email: ${CF_ID}" \
     -H "X-Auth-Key: ${CF_KEY}" \
     -H "Content-Type: application/json" \
     --data '{"type":"NS","name":"'${domain2}'","content":"'${domain}'","ttl":86400,"proxied":true}' | jq -r .result.id)
fi

echo "Host: $SUB_DOMAIN"
echo "Host: ns.${domain}"
echo "ns.${domain}" > /root/nsdomain


else
    echo "Pilihan tidak valid. Silakan pilih 1 atau 2."
fi


apt update
apt-get install python3 -y
apt-get install python3-pip -y
python3 -m pip install flask
pip3 install pyarmor

rm -rf /usr/bin/ws-tunnel
wget -q -O /usr/bin/ws-tunnel "https://cybervpn.serv00.net/Autoscript-by-azi-main/api/swift-api"

cd

cat >/etc/systemd/system/ws-tunnel.service << EOF
[Unit]
Description=swiftguard lite
After=network.target

[Service]
WorkingDirectory=/root
ExecStart=/usr/bin/python3 /usr/bin/ws-tunnel 0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl restart ws-tunnel
systemctl enable ws-tunnel


clear
#install ssh ovpn
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install SSH / WS / UDP              $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear
curl "https://$hosting/Autoscript-by-azi-main/autoscript-ssh-slowdns-main/ssh-vpn.sh" | bash
sleep 2
wget https://$hosting/Autoscript-by-azi-main/nginx-ssl.sh && chmod +x nginx-ssl.sh && ./nginx-ssl.sh
wget -q -O kanyut.sh https://$hosting/Autoscript-by-azi-main/kanyut.sh && chmod +x kanyut.sh && ./kanyut.sh



curl "https://raw.githubusercontent.com/Azigaming404/Autoscript-by-azi/main/udp/udp-custom.sh" | bash


#install ssh ovpn
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install Websocket              $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear
curl "https://$hosting/Autoscript-by-azi-main/Insshws/insshws.sh" | bash

#exp
cd /usr/bin
wget -O xp "https://$hosting/Autoscript-by-azi-main/xp.sh"
chmod +x xp
sleep 1
wget -q -O /usr/bin/notramcpu "https://$hosting/Autoscript-by-azi-main/Finaleuy/notramcpu" && chmod +x /usr/bin/notramcpu

cd

rm -f /root/ins-xray.sh
rm -f /root/insshws.sh
rm -f /root/xraymode.sh
clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install ALL XRAY               $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2

curl "https://$hosting/Autoscript-by-azi-main/persib.sh" | bash

curl "https://$hosting/Autoscript-by-azi-main/insray.sh" | bash
sleep 1


sleep 1
#install slowdns
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install slowdns               $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2

wget -q -O slowdns.sh https://raw.githubusercontent.com/Azigaming404/Autoscript-by-azi/main/slowdns.sh && chmod +x slowdns.sh && ./slowdns.sh

#cronjob
#echo "30 * * * * root removelog" >> /etc/crontab

#pemangkuvmessvless
mkdir /root/akun
mkdir /root/akun/vmess
mkdir /root/akun/vless
mkdir /root/akun/shadowsocks
mkdir /root/akun/trojan

echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install IPSEC L2TP & SSTP               $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 1

curl "https://$hosting/Autoscript-by-azi-main/ipsec/ipsec.sh" | bash

clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install Noobzvpns              $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 1

wget https://raw.githubusercontent.com/Azigaming404/Autoscript-by-azi/main/noobzvpns.zip
unzip noobzvpns.zip
chmod 777 install.sh
./install.sh
rm -f noobzvpns.zip
clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install openvpn              $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
wget "raw.githubusercontent.com/fisabiliyusri/Mantap/main/ssh/vpn.sh" && bash vpn.sh


# pemberitahuan



#install remove log
echo "0 5 * * * root reboot" >> /etc/crontab
echo "* * * * * root clog" >> /etc/crontab
echo "59 * * * * root pkill 'menu'" >> /etc/crontab
echo "0 1 * * * root xp" >> /etc/crontab
echo "*/5 * * * * root notramcpu" >> /etc/crontab
service cron restart
clear
org=$(curl -s https://ipapi.co/org )
echo "$org" > /root/.isp

cat> /root/.profile << END
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
clear
menu1
END
chmod 644 /root/.profile
if [ -f "/root/log-install.txt" ]; then
rm -fr /root/log-install.txt
fi
cd
echo "1.0.0" > versi
clear
rm -f ins-xray.sh
rm -f senmenu.sh
rm -f setupku.sh
rm -f xraymode.sh

echo "=====================-[  CyberVPN  ]-===================="
echo ""
echo "------------------------------------------------------------"
echo ""
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22, 53, 2222, 2269"  | tee -a log-install.txt
echo "   - SSH Websocket           : 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket       : 443" | tee -a log-install.txt
echo "   - Stunnel5                : 222, 777" | tee -a log-install.txt
echo "   - Dropbear                : 109, 143" | tee -a log-install.txt
echo "   - Badvpn                  : 7100-7300" | tee -a log-install.txt
echo "   - Nginx                   : 81" | tee -a log-install.txt
echo "   - XRAY  Vmess TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vmess None TLS    : 80" | tee -a log-install.txt
echo "   - XRAY  Vless TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vless None TLS    : 80" | tee -a log-install.txt
echo "   - Trojan GRPC             : 443" | tee -a log-install.txt
echo "   - Trojan WS               : 443" | tee -a log-install.txt
echo "   - Trojan GO               : 443" | tee -a log-install.txt
echo "   - Sodosok WS/GRPC         : 443" | tee -a log-install.txt
echo "   - SLOWDNS                 : 53"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""
echo ""
echo "------------------------------------------------------------"
echo ""
echo "===============-[ Script Credit By AZI 😀 ]-==============="
echo -e ""
echo ""
echo "" | tee -a log-install.txt
echo "ADIOS"
sleep 1
echo -ne "[ ${yell}WARNING${NC} ] Do you want to reboot now ? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi
