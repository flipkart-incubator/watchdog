from mongo_connection import mongo_client
from run_tools import run_tool
import os
import sys

def countVulns(ip,domain,type):
	cwd = os.getcwd()
	c = mongo_client()
	Configure = c.config.external.find()[0]
	#ip = sys.argv[1]
	#domain = sys.argv[2]
	#type = sys.argv[3]
	if(type == "selfServe"):
		DBName = Configure['SELF_SERVE_DATABASE']
	else:
		DBName = Configure['DATABASE']
	collection = c[DBName].vulnerabilities
	newCollection = []

	serverAddress = "http://127.0.0.1"


	data = collection.find_one({"ip":ip})

	# print collection.find().count()
	# print collection.find()[0]

	url = data['skipfish']

	fileUrl = serverAddress + str(url).split("html")[1]+"/index.html"

	command = "phantomjs loadspeed.js " + fileUrl + " > temp/"+ip.replace(".","-")+".html"
	run_tool(cmd=command)

	command = "python parser.py temp/"+ip.replace(".","-")+".html > temp/"+ip.replace(".","-")+".txt"
	run_tool(cmd=command)

	f = open("temp/"+ip.replace(".","-")+".txt")
	number = f.read().split("\n")[0]

	c[DBName].vulnerabilities.update({"ip":ip},{"$set":{"count":number}})
	f.close()

if __name__== "__main__":
        countVulns(sys.argv[1],sys.argv[2],sys.argv[3])


