import os
from subprocess import Popen
from mongo_connection import mongo_client
import logging
import time,datetime

client = mongo_client()
db = client.config
cursor = db.external.find()
logFile = cursor[0]['SELF_SERVE_PATH_LOGFILE']
database = cursor[0]['SELF_SERVE_DATABASE']
db =  client[database]
logging.basicConfig(filename = logFile,filemode = 'w',format='%(levelname)s:%(message)s',level=logging.DEBUG)

cursor = db.onGoingIp.find()

for document in cursor:
	ip = document['ip']
	domain = document['domain']
	if domain == "":
		domain = "null"
	serv =  db.services	
	os.system("python findPorts.py "+str(ip)+" "+str(domain)+" selfServe")
	ts = time.time()
	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
	db.services.update({"ip":ip},{"$set":{"time":st}})
	if serv.find({"ip":ip,"80":{"$exists":True}}).count()  > 0 or serv.find({"ip":ip,"443":{"$exists":True}}).count() > 0:
		logging.info("Finding Vulnerability")
		p = Popen("sudo python findVulnerability.py "+str(ip)+" "+str(domain)+" selfServe",shell = True)
		os.system("python findTechnology.py "+str(ip)+" "+str(domain)+" selfServe")
	else:
		logging.info("Both 80 and 443 are closed corresponding to ip: "+str(ip))

try:
	while (p.poll() is None):
		time.sleep(10)
except:
	pass


onGoingIp = db.onGoingIp
onGoingIp.remove({})
