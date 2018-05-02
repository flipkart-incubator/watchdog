import socket, sys
from mongo_connection import mongo_client

def fill_Inventory(filename,action=None):
    client = mongo_client()
    db = client.testingExternal

    if not filename:
        filename = 'subdomains.txt'

    lines = ""
    with open(filename) as f:
        lines = f.readlines()

    if f:
        f.close()

    if action == "replace":
        db.ipInventory.remove()

    i = 1
    for line in lines:
        if line.strip() != "":
            domain = {}
            try:
                ip = socket.gethostbyname(line.strip())
                domain['ip'] = ip
                domain['domain'] = line.strip()
                print str(i)+". ",
		print domain,
                count = db.ipInventory.count({'domain': line.strip(),'ip': ip})
                if count == 0:
                    print db.ipInventory.insert(domain)
		else:
		    print "Already in DB"
                i=i+1

            except Exception as ae:
		print ae
                pass

if __name__ == '__main__':
    fill_Inventory()

