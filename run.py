import os
import sys
import argparse
from fillInventory import fill_Inventory
from start_scans import start_scan
from configdb import config_db
from run_tools import run_tool

def main(argv):
    os.environ["LC_ALL"] = "en_US.UTF-8";
    parser = argparse.ArgumentParser()
    parser.add_argument("-c","--config",help="to configure db structure",action="store_true")
    parser.add_argument("-iA","--inventory-append",help="to append target to IP Inventory")
    parser.add_argument("-iR","--inventory-replace",help="to replace targets in IP Inventory")
    parser.add_argument("-u","--updateCVEs",help="to configure or update CVE database", choices=['install','map','update'])
    parser.add_argument("-s","--start",help="to start scaning engine",action="store_true")

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.inventory_append:
        fill_Inventory(args.inventory_append, action="append")

    if args.inventory_replace:
        fill_Inventory(args.inventory_replace,action="replace")

    if args.config:
        config_db()

    if args.updateCVEs:
        if args.updateCVEs == "install":
            cmd = "python3 ./Tools/cve-search-master/sbin/db_mgmt.py -p"
            run_tool(cmd,verbose=True)

        if args.updateCVEs == "map":
            cmd = "python3 Tools/cve-search-master/sbin/db_mgmt_cpe_dictionary.py"
            run_tool(cmd,verbose=True)

        if args.updateCVEs == "update":
            cmd = "python3 Tools/cve-search-master/sbin/db_updater.py"
            run_tool(cmd,verbose=True)

    if args.start:
        start_scan()


if __name__== "__main__":
    main(sys.argv)


