# WatchDog

WatchDog in an Organization will serve two important purposes:
Monitor External Assets and create an inventory of softwares used.
Monitor for open source libraries across Organization's code base.

### installing watchdog

- prerequisites & softwares
    
    ```
    * Ubuntu 16.04+
    * Apache2 + PHP5.6 + Mongo
    * PyV8
    ```

- clone watchdog repository

    ```
    $ git clone https://github.fkinternal.com/Flipkart/watchdog-new.git
    $ cd watchdog-new
    ```

- Install PyV8
    - incase, if you are facing any issues in installing, follow below steps (workaround, works for Ubuntu 16+)

    ```
    $ export LC_ALL=C
    $ cd <some directory>
    $ pip install -e git://github.com/brokenseal/PyV8-OS-X#egg=pyv8
    $ git clone https://github.com/emmetio/pyv8-binaries.git
    $ unzip pyv8-binaries/pyv8-linux64.zip (or unzip appropriate zip file based on kernal version)
    $ mv *PyV8* src/pyv8/pyv8/.
    ```
    
- update your subdomains.txt file with your target subdomains
    - ex: www.github.com

- run installation script
    ```
    $ sudo chmod +x install.sh
    $ sudo ./install.sh
    ```

- during installation, installation script prompts for web root directory. Default directory `/var/www/html` will be taken automatically if not provided explicitly with-in `10 secs`

### scanning with watchdog

- watchdog can be run by using following command

    ```
    $ sudo python run.py
    ```

    ```
    root@projectWatchdog:/watchdog# python run.py
    usage: run.py [-h] [-c] [-iA INVENTORY_APPEND] [-iR INVENTORY_REPLACE]
                  [-u {install,map,update}] [-s]

    optional arguments:
      -h, --help            show this help message and exit
      -c, --config          to configure db structure
      -iA INVENTORY_APPEND, --inventory-append INVENTORY_APPEND
                            to append target to IP Inventory
      -iR INVENTORY_REPLACE, --inventory-replace INVENTORY_REPLACE
                            to replace targets in IP Inventory
      -u {install,map,update}, --updateCVEs {install,map,update}
                            to configure or update CVE database
      -s, --start           to start scaning engine

    ```

### configuring CVE-DB

- install cve db using below command (required to run atleast once)

    ```
    $sudo python run.py -u install
    ```

- map cves with cpes using below command (required to run atleast once)

    ```
    $sudo python run.py -u map
    ```

- you can update the DB by using below command (optional)

    ```
    $sudo python run.py -u update
    ```

### need to add new domains for scanning?

- update subdomains.txt file with new (sub)domains and run below commands

    ```
    $ sudo python run.py -iA subdomains.txt (for appending targets to existing inventory)
    $ sudo python run.py -iR subdomains.txt (for replacing targets in existing inventory)
    ```

- Frontend can be accessed from ```http://localhost/index.php``` (or replace localhost with your web server address)

### Lead Developer
- Mohan Krushna K (mohan.kk@flipkart.com)

### Project Lead 
- Prajal Kulkarni (prajal.kulkarni@flipkart.com)

### Project Team:
- Shubham Bansal 
- Prabhav Adhikari
- Rohit Agrawal
   
### Credits
- Flipkart Security Team
- NMAP
- [Wapiti](http://wapiti.sourceforge.net/)
- Skipfish
- [Phantalyser](https://github.com/mlconnor/phantalyzer)
- [CVE Search](https://github.com/cve-search/cve-search)


