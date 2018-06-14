from mongo_connection import mongo_client
from run_tools import run_tool
import sys
import commands
import hashlib
import logging


def portScan(ip,domain,type):
	# config file
	client = mongo_client()
	db = client.config
	cursor = db.external.find()

	# check for the selfServe or org scan
	if(type == "selfServe"):
		logFile = cursor[0]['SELF_SERVE_PATH_LOGFILE']
		database = cursor[0]['SELF_SERVE_DATABASE']
	else:
		logFile = cursor[0]['PATH_LOGFILE']
		database = cursor[0]['DATABASE']
	db = client[database]

	services = db.services

	#log file
	logging.basicConfig(filename = logFile,format='%(levelname)s:%(message)s',level=logging.DEBUG)


	logging.info("finding Open Ports")
	host = ip # to be passed as a parameter
	ports = []
	version = []
	false_positive =  []
	try:
		services = run_tool(name='nmap',ip=host) # nmap command
		logging.info(services)
		services = services[1].split(":")[2]
		services = services.split(",")
		for i in range(len(services)):    # each iteration will correspond to one port
			services[i] = services[i].strip()
			ports.append(services[i].split("/")[0])
			version.append(services[i].split("//")[2].split("/")[0])
	except Exception as e:
		logging.error("Some issue with Nmap. Issue: "+str(e))
	if len(ports) != 0:  # calculating md5 sum and updating the database
		md5 = ''.join(sorted(ports))
		md5 = hashlib.md5(md5).hexdigest()
		if domain == "null":
			domain = ""
		services = db.services
		if  services.find({"ip":ip,"md5":md5}).count() == 0:
			for cnt in range(len(ports)):
				false_positive.append("")
			checking = services.find_one({"ip":ip})
			if services.find({"ip":ip}).count() > 0:  # if ports have changed then delete that entry from database
				logging.info("Ports have changed.")
				services.remove({"ip":ip})
			else:
				logging.info("This ip is scanned for the first time.") 
			service = {"ip":ip,"domain":domain,"md5":md5}  # insert port details in database
			services.insert_one(service)
			for i in range(len(ports)):	# setting false_positive
				if checking != None:
					for ch in checking:
						if ports[i] == ch.encode('ascii','ignore') and version[i] == checking[ch]['version'].encode('ascii','ignore'):
							false_positive[i] = checking[ch]['false_positive']
				try:
					if false_positive[i] == "":
						false_positive[i] = "0"
				except:
					false_positive[i] = "0"

				try:
					if not version[i]:
						version[i] = ""
				except:
					version[i] = ""

				services.update({"ip":ip},{"$set":{ports[i]:{"version":version[i],"false_positive":false_positive[i]}}})
				logging.info(str(ports[i])+" has version "+str(version[i]))
		else:   # updating domain if it is not present before
			if services.find_one({"ip":ip})['domain'].encode('ascii','ignore') == "":
				services.update({"ip":ip},{"$set":{"domain":domain}})
			logging.info("Same ports as before")
	else:   # if no port is identified
		services = db.services
		if services.find({"ip":ip}).count() == 0:
			md5 = hashlib.md5('').hexdigest()
			serv = {"ip":ip,"domain":domain,"md5":md5}
			services.insert_one(serv)

if __name__== "__main__":
	portScan(sys.argv[1],sys.argv[2],sys.argv[3])







