#apt-get update

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

export LC_ALL=en_US.UTF-8
if grep -q "export LC_ALL=en_US.UTF-8" ~/.bash_profile;then
   echo ""
else
   echo "export LC_ALL=en_US.UTF-8" >> ~/.bash_profile
fi

echo "[+] Installing Dependencies"

echo "deb http://cz.archive.ubuntu.com/ubuntu trusty main universe" | sudo tee /etc/apt/sources.list.d/skipfish.source.list
sudo apt-get install -y wget curl python-pip python3 python3-pip unzip
sudo pip install -r external-requirements.txt

echo "[+] Setting up DataBase"
echo "[+] Installing Mongo Server"
sudo apt-get install -y mongodb-server
sudo mkdir -p /data/db
sudo service mongodb restart

echo "[+] Setting up Configs"

echo -n "Enter Web application root path: (default: /var/www/html) "
read -t 10 WEB_DIR
echo ""

sudo python configdb.py ${WEB_DIR:-/var/www/html}

cwd=$(pwd)

sudo mkdir -p ${cwd}/Tools/skipfish
sudo mkdir -p ${WEB_DIR:-/var/www/html}/reports/
sudo mkdir -p ${WEB_DIR:-/var/www/html}/reports/outputWapiti/
sudo mkdir -p ${WEB_DIR:-/var/www/html}/reports/outputSkipfish/

sudo chmod -R 777 ${cwd}/Tools
sudo chmod -R 777 ${WEB_DIR:-/var/www/html}/reports

cd ${cwd}/Tools

echo "[+] Installing NMap"
sudo apt-get install -y nmap

echo "[+] Installing NodeJs"
curl -sL https://deb.nodesource.com/setup_9.x | sudo -E bash - && apt-get install -y nodejs
sudo ln -s /usr/bin/nodejs /usr/sbin/node

echo "[+] Installing npm"
sudo apt-get install -y npm

echo "[+] Installing PhantomJs"
# wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 -O phantomjs-2.1.1-linux-x86_64.tar.bz2
# tar xvf phantomjs-2.1.1-linux-x86_64.tar.bz2

sudo rm /usr/local/share/phantomjs
sudo rm /usr/local/bin/phantomjs
sudo rm /usr/bin/phantomjs

sudo ln -s ${cwd}/Tools/phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/share/phantomjs
sudo ln -s ${cwd}/Tools/phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs
sudo ln -s ${cwd}/Tools/phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/bin/phantomjs
sudo rm -rf ${cwd}/Tools/phantomjs-2.1.1-linux-x86_64.tar.bz2

sudo apt-get install libfontconfig


echo "[+] Installing Phantalyzer"
# wget https://github.com/mlconnor/phantalyzer/archive/master.zip -O phantalyzer-master.zip
# unzip phantalyzer-master.zip
# sudo rm -rf ${cwd}/Tools/phantalyzer-master.zip

echo "[+] Installing Wapiti"
# wget https://excellmedia.dl.sourceforge.net/project/wapiti/wapiti/wapiti-2.3.0/wapiti-2.3.0.tar.gz -O wapiti.tar.gz
# tar xvf wapiti.tar.gz

cd ${cwd}/Tools/wapiti-2.3.0
sudo python setup.py install
# sudo rm -rf ${cwd}/Tools/wapiti.tar.gz

echo "[+] Installing SkipFish"
sudo apt-get install skipfish

cd ${cwd}/Tools
echo "[+] Installing CVE-Search"
# wget https://github.com/cve-search/cve-search/archive/master.zip -O cve-search-master.zip
# unzip cve-search-master.zip
# sudo rm -rf ${cwd}/Tools/cve-search-master.zip

cd ${cwd}/Tools/cve-search-master
sudo apt-get install -y libxml2-dev libxslt-dev python-dev python-lxml python3-lxml
sudo pip3 install -r requirements.txt

# echo "[+] Updating CVE-Search DataBase. This might take a while. Go have a cookie.. :)"
# python3 sbin/db_mgmt.py -p
# python3 sbin/db_mgmt_cpe_dictionary.py

echo "[+] Verifying if all the tools are working properly"
wapiti -h
skipfish -h
phantomjs -v
nmap -v
node --version
npm -v

echo "[+] Installing Front end"
sudo apt-get purge -y `dpkg -l | grep php| awk '{print $2}' |tr "\n" " "`

sudo apt-get install -y python-software-properties
sudo add-apt-repository ppa:ondrej/php
sudo apt-get update
sudo apt-get install -y apache2 php5.6 php5.6-mongo

sudo cp -r ${cwd}/Frontend/* ${WEB_DIR:-/var/www/html}/.

sudo service apache2 restart

echo -e "${RED}[*] Installation compelted successfully${NC}"
echo -e "${RED}[*] you can run WATCHDOG by using ${GREEN} python run.py${NC}"
echo -e "${RED}[*] you can see the magic of WATCHDOG by browsing ${GREEN} http://localhost${NC}"




