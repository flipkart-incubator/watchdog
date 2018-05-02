import os, sys
from subprocess import Popen
from mongo_connection import mongo_client
import logging
from findPorts import portScan
from findVulnerability import vulnerabilityScan
from findTechnology import technologyScan

def start_scan():
	# config database
	client = mongo_client()

	db = client.config

	# select configurations
	cursor = db.external.find()

	if not cursor or cursor.count() == 0:
		print "[!] Please configure the DB first by running below command."
		print "\t$ docker run -t -i --rm --link <your mongo container name>:mongodb watchdog -c"
		sys.exit(1)

	logFile = cursor[0]['PATH_LOGFILE']
	database = cursor[0]['DATABASE']
	db =  client[database]

	# log file
	logging.basicConfig(filename = logFile,filemode = 'w',format='%(levelname)s:%(message)s',level=logging.DEBUG)

	# ips
	cursor = db.ipInventory.find()
	print "Total IPs in database: "+str(cursor.count())

	# each  iteration corresponds to one ip
	for document in cursor:
		ip = document['ip']
		domain = document['domain']
		if domain == "":
			domain = "null"
		serv =  db.services
		
		#os.system("python findPorts.py "+str(ip)+" "+str(domain)+" org") # call findPorts
		print "starting portscan"
		portScan(str(ip),str(domain),"org")
		#checking whether 80 or 443 is open
		if serv.find({"ip":ip,"80":{"$exists":True}}).count()  > 0 or serv.find({"ip":ip,"443":{"$exists":True}}).count() > 0:
			logging.info("Finding Vulnerability")
			# p = Popen("sudo python findVulnerability.py "+str(ip)+" "+str(domain)+" org",shell = True) # call findVulnerability
			vulnerabilityScan(str(ip),str(domain),"org")
			technologyScan(str(ip),str(domain),"org")
			#os.system("python findTechnology.py "+str(ip)+" "+str(domain)+" org") # call findTechnology
		else:
			logging.info("Both 80 and 443 are closed corresponding to ip: "+str(ip))

if __name__ == '__main__':
    start_scan()

