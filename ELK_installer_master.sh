#!/bin/bash
#
: Author: evilcomrade
#
red=$'\e[1;31m'
green=$'\e[1;32m'
blue=$'\e[1;34m'
end=$'\e[0m'

if [ "$EUID" -ne 0 ]; then
        echo "${red}[+] Needs to be run as root. Exiting...${end}"
        exit
else
	echo "${green}[+] We are root and good to go!"
fi

# Backup existing ELK_logfile
if [ -f /var/log/ELK_install.log ]; then
	mv /var/log/ELK_install.log /var/log/ELK_install_$(date +'%Y%m%d-%H%M%S').log
fi

logfile=/var/log/ELK_install.log
mkfifo ${logfile}.pipe
tee < ${logfile}.pipe $logfile &
exec &> ${logfile}.pipe
rm ${logfile}.pipe

echo "${blue}[+] Installing a few dependencies (Openjdk, nginx, openssh-server & apt-transport ) for ELK"
echo "[+] This could take a while...${end}"
apt-get update  &>> $logfile

apt-get -y install openjdk-8-jre-headless apt-transport-https openssh-server nginx &>> $logfile

echo "${blue}[+] Installing Elastic PGP signing key"
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - 
echo "${green}[+] Done"

echo "${blue}[+] Adding Elastic Packages source list definitions to your sources list"
echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-5.x.list 
echo "${green}[+] Done"

echo "${blue}[+] Installing & Configuring Elastic Search"
apt-get update &>> $logfile 
apt-get -y install elasticsearch &>> $logfile
sed -i 's/#network.host: 192.168.0.1/network.host: localhost/g' /etc/elasticsearch/elasticsearch.yml
echo "${green}[+] Done"

echo "${blue}[+] Starting Elastic Search"
systemctl daemon-reload &>> $logfile
systemctl enable elasticsearch.service &>> $logfile
systemctl start elasticsearch.service &>> $logfile
if (systemctl -q is-active elasticsearch.service)
    then
    	echo "${green}[+] Elastic Search is up and running."
else
	echo "${red}[+] Logstash has issues check the logfile $logfile."
fi

echo "${blue}[+] Installing & Configuring Kibana"
apt-get update &>> $logfile 
apt-get --force-yes -y  install kibana &>> $logfile
sed -i 's/#server.host: "localhost"/#server.host: "localhost"/g' /etc/kibana/kibana.yml
echo "${green}[+] Done"

echo "${blue}[+] Starting Kibana"
systemctl daemon-reload &>> $logfile
systemctl enable kibana.service &>> $logfile
systemctl start kibana.service &>> $logfile
if (systemctl -q is-active kibana.service)
    then
    	echo "${green}[+] Kibana is up and running."
else
	echo "${red}[+] Kibana has issues check the logfile $logfile."	
fi

while true; do
	read -p "${red}[+] Create a password to log into our Kibana web interface:${end} " kibanapw1
	read -p "${red}[+] Please confirm:${end} " kibanapw2
	if [ "${kibanapw1}" == "${kibanapw2}" ]; then
		break
	fi
done
echo "kibadmin:$(openssl passwd -apr1 $kibanapw1)" | tee -a /etc/nginx/htpasswd.users
echo "Username: ${end}${red}kibadmin${end}"
echo "${green}[+] Password set."

echo "${blue}[+] Configuring nginx"
mv /etc/nginx/sites-available/default /etc/nginx/sites-available/original_backup_default &>> $logfile

read -p "${red}[+] Enter IP Address:${end}" IP_ADDRESS

echo "server {"> /etc/nginx/sites-available/default
echo "    listen 80;">> /etc/nginx/sites-available/default
echo "    server_name $IP_ADDRESS;">> /etc/nginx/sites-available/default
echo "    auth_basic \"Restricted Access\";">> /etc/nginx/sites-available/default
echo "    auth_basic_user_file /etc/nginx/htpasswd.users;">> /etc/nginx/sites-available/default
echo "    location / {">> /etc/nginx/sites-available/default
echo "        proxy_pass http://localhost:5601;">> /etc/nginx/sites-available/default
echo "        proxy_http_version 1.1;">> /etc/nginx/sites-available/default
echo "        proxy_set_header Upgrade \$http_upgrade;">> /etc/nginx/sites-available/default
echo "        proxy_set_header Connection 'upgrade';">> /etc/nginx/sites-available/default
echo "        proxy_set_header Host \$host;">> /etc/nginx/sites-available/default
echo "        proxy_cache_bypass \$http_upgrade;        ">> /etc/nginx/sites-available/default
echo "    }">> /etc/nginx/sites-available/default
echo "}">> /etc/nginx/sites-available/default

echo "${blue}[+] Testing nginx config"
systemctl enable nginx.service &>> $logfile
nginx -t &>> $logfile
systemctl restart nginx.service &>> $logfile
if (systemctl -q is-active nginx.service)
    then
    echo "${green}[+] Nginx is up and running. You should be able to log into Kibana"
else
	echo "${red}[+] Nginx has issues check the logfile $logfile."
fi

echo "${blue}[+] Installing & Configuring Logstash"
apt-get update &>> $logfile 
apt-get --force-yes -y  install logstash &>> $logfile
mkdir -p /etc/pki/tls/certs &>> $logfile
mkdir /etc/pki/tls/private &>> $logfile

sed -i "s/# Extensions for a typical CA/subjectAltName\ \=\ IP\:\ $IP_ADDRESS/g"  /etc/ssl/openssl.cnf

cd /etc/pki/tls &>> $logfile
openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt &>> $logfile
echo "${red}[+] Your cert has been stored to the location below."
echo "/etc/pki/tls/certs/logstash-forwarder.crt${end}"
echo "${green}[+] Done"

echo "${blue}[+] Creating custom Logstash configuration files."
if [ -f /etc/logstash/conf.d/02-beats-input.conf ]; then
	echo "${blue}[+] There's an existing beats input config file.. Backing it up."
	mv /etc/logstash/conf.d/02-beats-input.conf /etc/logstash/conf.d/02-beats-input.conf.bak &>> $logfile
else	
	touch /etc/logstash/conf.d/02-beats-input.conf &>> $logfile
	echo "input {">> /etc/logstash/conf.d/02-beats-input.conf
	echo "  beats {">> /etc/logstash/conf.d/02-beats-input.conf
	echo "    port => 5044">> /etc/logstash/conf.d/02-beats-input.conf
	echo "    add_field => { \"[@metadata][source]\" => \"winlogbeat\"}">> /etc/logstash/conf.d/02-beats-input.conf
	echo "    ssl => true">> /etc/logstash/conf.d/02-beats-input.conf
	echo "    ssl_certificate => \"/etc/pki/tls/certs/logstash-forwarder.crt\"">> /etc/logstash/conf.d/02-beats-input.conf
	echo "    ssl_key => \"/etc/pki/tls/private/logstash-forwarder.key\"">> /etc/logstash/conf.d/02-beats-input.conf
	echo "  }">> /etc/logstash/conf.d/02-beats-input.conf
	echo "}">> /etc/logstash/conf.d/02-beats-input.conf
fi
if [ -f /etc/logstash/conf.d/50-elasticsearch-output.conf ]; then
	echo "${blue}[+] There's an existing Elastic search output config file.. Backing it up."
	mv /etc/logstash/conf.d/50-elasticsearch-output.conf /etc/logstash/conf.d/50-elasticsearch-output.conf.bak &>> $logfile
else 
	touch /etc/logstash/conf.d/50-elasticsearch-output.conf &>> $logfile
	echo "output {">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "  if [@metadata][source] == \"winlogbeat\" {">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "    elasticsearch {">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "      hosts => [\"localhost:9200\"]">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "      sniffing => true">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "      manage_template => false">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "      index => \"%{[@metadata][beat]}-%{+YYYY.MM.dd}\"">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "      document_type => \"%{[@metadata][type]}\"">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "    }">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "  }">> /etc/logstash/conf.d/50-elasticsearch-output.conf
	echo "}">> /etc/logstash/conf.d/50-elasticsearch-output.conf
fi
echo "${blue}[+] Starting logstash."
systemctl daemon-reload &>> $logfile
systemctl enable logstash.service &>> $logfile
systemctl start logstash.service &>> $logfile
if (systemctl -q is-active kibana.service)
    then
    	echo "${green}[+] Logstash is up and running."
else
	echo "${red}[+] Logstash has issues check the logfile $logfile."
fi
echo "${blue}[+] The log file for ELK is located at: $logfile."
echo "${green}[+] We should be all good."