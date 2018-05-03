from mongo_connection import mongo_client
from select import select
import sys

def config_db(argv):
	c = mongo_client()
	db = c.config
	db.external.remove()

	if len(sys.argv) < 3:
		web_dir = '/var/www/html'
	else:
		web_dir = sys.argv[2]

	print web_dir
	db.external.insert_one({
		'SELF_SERVE_PATH_SKIPFISH': web_dir+'/reports/selfServeOutputSkipfish/',
		'SELF_SERVE_DATABASE': 'selfTestingExternal', 
		'PATH_WAPITI': web_dir+'/reports/outputWapiti/', 
		'DATABASE': 'testingExternal', 
		'SELF_SERVE_PATH_WAPITI': web_dir+'/reports/selfServeOutputWapiti/', 
		'TIMEOUT_VUL': '180', 
		'TIMEOUT_TECH': '30', 
		'PATH_LOGFILE': 'external.log', 
		'PATH_SKIPFISH': web_dir+'/reports/outputSkipfish/', 
		'SELF_SERVE_PATH_LOGFILE': 'selfServe.log'
	})

	db.internal.insert_one({
	   'REPO_PATH':"",
	   'SCALE_CRITICAL_VUL_CVE_EXTERNAL':8.3,
	   'SELF_SERVE_DATABASE':'Self_Serve_Internal_Testing',
	   'SCALE_MEDIUM_VUL_CVE_EXTERNAL':5.0,
	   'DATABASE':'Internal_Testing',
	   'ORGANISATION':'Flipkart',
	   'GIT_TOKEN':'prajal:b9fa972c4c45c586c1bcac5a25b95abcd8cf047a',
	   'SCALE_MEDIUM_VUL_CVE_INTERNAL':5.0,
	   'DEPENDENCY_PATH_LOGFILE':'dependency_log.log',
	   'SELF_SERVE_SOURCE_PATH_LOGFILE':'self_serve_source_log.log',
	   'SELF_SERVE_DEPENDENCY_PATH_LOGFILE':'self_serve_dependency_log.log',
	   'SOURCE_PATH_LOGFILE':'source_log.log',
	   'SELF_SERVE_TIME_OUT':30,
	   'TIME_OUT':30,
	   'SCALE_HIGH_VUL_CVE_INTERNAL':7.5,
	   'SCALE_HIGH_VUL_CVE_EXTERNAL':7.5,
	   'SCALE_CRITICAL_VUL_CVE_INTERNAL':8.3,
	   'SCALE_HIGH_VUL_REPO':8.3
	})

	return web_dir

if __name__ == '__main__':
	config_db(sys.argv)

