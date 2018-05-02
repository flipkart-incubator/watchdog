from wappalyzer import Wappalyzer
from builtwith import builtwith
from run_tools import run_tool
import json
import sys
import subprocess
import commands
from mongo_connection import mongo_client
import time
import signal
import logging 


def technologyScan(ip,domain,type):
	# config database
	client = mongo_client()
	db = client.config
	cursor = db.external.find()
	#type = sys.argv[3]

	# checking for selfServe of org scan and setting the paramter
	if(type == "selfServe"):
	        logFile = cursor[0]['SELF_SERVE_PATH_LOGFILE']
	        database = cursor[0]['SELF_SERVE_DATABASE']
	else:
	        logFile = cursor[0]['PATH_LOGFILE']
	        database = cursor[0]['DATABASE']
	TIMEOUT = int(cursor[0]['TIMEOUT_TECH'])
	db = client[database]

	# log file
	logging.basicConfig(filename = logFile,format='%(levelname)s:%(message)s',level=logging.DEBUG)

	# timeout
	def signal_handler(signum,frame):
		raise Exception("Timed Out!")
	signal.signal(signal.SIGALRM, signal_handler)

	#ip = sys.argv[1]
	#domain = sys.argv[2]
	w = Wappalyzer()
	serv = db.services
	if domain != "null":
		host =  domain   # host is the parameter to be passed
	else:
		host = ip

	if domain == "null":
		domain = ""

	# checking whether to scan through 80 or 443
	if serv.find({"ip":ip,"443":{"$exists":True}}).count() > 0:
		prefix = "https://"
	elif serv.find({"ip":ip,"80":{"$exists":True}}).count() > 0:
		prefix = "http://"
	component = {}


	# every 3rd party tools is scanning 6 times, if it finds the technology than it stops

	# wappalyzer
	count = 6
	while (count):
		if count <= 3:
			host = ip   # host is changed to ip after 3 scan
		count -= 1
		logging.info("Wappalyzer working on "+host)
		signal.alarm(TIMEOUT)
		try:  # calling wappalyzer
			wapp = w.analyze(prefix+host)
		except Exception as e:
			logging.error("Issues with wappalyzer: "+str(e))
			signal.alarm(0)
			continue
		signal.alarm(0)
		logging.info(wapp)
		if len(wapp) == 0: # checking for output
			logging.info("No output.")
			if count != 0:
				logging.info("Sleeping for 10 seconds.")
				time.sleep(10)
			continue
		for key in wapp:
			component[key.lower()] = wapp[key][unicode('version')]
		break

	# builtwith
	if domain != "":
		host = domain
	else:
		host = ip
	count = 6
	while(count):
		if count <= 3:
			host = ip
		count -= 1
		logging.info("Builtwith working on "+host)
		signal.alarm(TIMEOUT)
		try:  # builtwith working
			bw = builtwith(prefix+host)
		except Exception as e:
			logging.error("Issues with builtwith: "+str(e))
			signal.alarm(0)
			continue
		signal.alarm(0)
		logging.info(bw)
		if len(bw) == 0:
			logging.info("No output.")
			if count != 0:
				logging.info("Sleeping for 10 seconds.")
				time.sleep(10)
			continue
		for keys in bw: # checking for output
			for key in bw[keys]:
				if key not in component.keys():
					component[key.lower()] = ""
		break


	# phantalyzer
	if domain != "":
	        host = domain
	else:
	       host = ip
	count = 6
	while (count):
		if count <= 3:
			host = ip
		count -= 1 
		logging.info("Phantalyzer working on "+host)
		signal.alarm(TIMEOUT)
		try:
			phanta = run_tool(name="phantomjs",prefix=prefix,domain=host)
		except Exception as e:
			logging.error("Issue with phantalyzer: "+str(e))
		signal.alarm(0)
		try:
			phanta = phanta[1]
			phanta = phanta.strip()
			logging.info(phanta)
			if phanta == "":
				logging.info("No output.")
				if count != 0:
					logging.info("Sleeping for 10 seconds.")
					time.sleep(10)
				continue
			phanta = phanta.split("\n")
			phanta[0] = phanta[0].strip()
			phanta = phanta[0].split(":")[1]
			if phanta == "" or phanta.strip() == '160':
				logging.info("No output.")
				if count != 0:
					logging.info("Sleeping for 10 seconds.")
					time.sleep(10)
				continue
			phanta  = phanta.split("|")
			for te in phanta:
				te = te.strip()
				if te not in component.keys() and te != "":
					component[te.lower()] = ""
			break
		except Exception as e:
			logging.error("Issue with phantalyzer: "+str(e))


	# wappalyzer extension
	if domain != "":
	       host = domain
	else:
	        host = ip
	count = 6
	while(count):
		if count <= 3:
			host = ip
		count -= 1
		logging.info("Wappalyzer extension working on "+host)
		signal.alarm(TIMEOUT)
		try:
			cmd = "phantomjs src/drivers/phantomjs/driver.js "+prefix+host
			phantjs = run_tool(cmd=cmd)
		except Exception as e:
			logging.error("Issue with phantomjs code: "+str(e))
		signal.alarm(0)
		try:
			logging.info(phantjs[1].strip())
			if phantjs[1].strip() == "":
				logging.info("No output.")
				if count != 0:
					logging.info("Sleeping for 20 seconds.")
					time.sleep(2)
				continue
			phantjs = json.loads(phantjs[1])
			phantjs = phantjs['applications']
			if len(phantjs) == 0:
				logging.info("No output.")
				if count != 0:
					logging.info("Sleeping for 20 seconds.")
					time.sleep(20)
				continue
			for i in range(len(phantjs)):
				if (phantjs[i][unicode('name')]).lower() not in component.keys():	
					component[(phantjs[i][unicode('name')]).lower()] = phantjs[i][unicode('version')] 
				elif component[(phantjs[i][unicode('name')]).lower()] == "":
					component[(phantjs[i][unicode('name')]).lower()] = phantjs[i][unicode('version')]
			break
		except Exception as e:
			logging.error("Phantomjs code not working. Issues: "+str(e))

	# finding cves
	try:
		for key in component:
			temp  = {}
			temp['version'] =  component[key]
			allCve = []
			if component[key] == "":
				temp['cves'] = allCve
				temp['false_positive'] = "0"
				component[key] = temp
				continue

			cmd = "python3 Tools/cve-search-master/bin/search.py -p "+str(key).lower().replace(" js",".js").replace(" ","_").replace("apache","apache:http_server")+":"+str(component[key])+" -o json"
			cves = run_tool(cmd=cmd)
			cves =  cves[1]
			size = len(cves.split("\n"))
			if size == 1 and cves == "":
				temp['cves'] = allCve
				temp['false_positive'] =  "0"
				component[key] = temp
				continue
			for j in range(size):
				cve = {}
				tt = json.loads(cves.split("\n")[j])
				cve['id'] = tt['id']
				cve['cvss'] = tt['cvss']
				allCve.append(cve)
			temp['cves'] =  allCve
			temp['false_positive'] = "0"
			component[key] = temp
	except Exception as e:
		logging.error("Issues with finding cves. Issues: "+str(e))


	technologies = db.technologies
	checking = technologies.find_one({"ip":ip})
	if technologies.find({"ip":ip}).count() > 0:
		technologies.remove({"ip":ip})
	technology = {"ip":ip,"domain":domain}
	technologies.insert_one(technology)
	for key in component:
		try:
			for ch in checking:
				if key.replace("."," ") == ch.encode('ascii','ignore') and component[key]['version'] == checking[ch]['version'].encode('ascii','ignore'):
					component[key]['false_positive'] = checking[ch]['false_positive']
		except Exception as e:
			print "Issues with updating false positive: "+str(e)
		technologies.update({"ip":ip},{"$set":{str(key.replace("."," ")):component[key]}})
		print key+" with version "+str(component[key])


if __name__== "__main__":
	technologyScan(sys.argv[1],sys.argv[2],sys.argv[3])







