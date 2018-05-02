import os
import sys
import commands
import hashlib
import logging
from subprocess import Popen
from subprocess import call

cwd = os.getcwd()

def run_tool(cmd=None, name=None, ip=None, prefix=None, domain=None, type=None, path=None, process=False, timeout=None, verbose=None):
	if(name == "nmap"):
		cmd = "nmap -n -Pn -A --open -oG  - "+str(ip)+" | grep Ports"

	if(name == "wapiti"):
		cmd = "wapiti "+str(domain)+" -b domain -t 1 -o "+path

	if(name == "skipfish"):
		cmd = "skipfish -MEU -W "+cwd+"/Tools/skipfish/new_dict_"+domain+".wl -o  "+path+" -k "+str(timeout/3600)+":"+str((timeout%3600)/60)+":"+str((timeout%3600)%60)+" -u "+str(prefix+domain)

	if(name == "phantomjs"):
		cmd = "phantomjs "+cwd+"/Tools/phantalyzer-master/phantalyzer.js "+str(domain)+" | egrep 'detectedApps|wappalyzerDetected'"

	try:
		print cmd
		if process:
			pid = Popen("exec "+cmd,shell = True)
			return pid
		elif verbose:
			call(cmd.split())
			return True
		else:
			output = commands.getstatusoutput(cmd) # nmap command
			return output

	except Exception as e:
		logging.error("Some issue with "+str(name)+". Issue: "+str(e))

	return ""

