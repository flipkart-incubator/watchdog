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

	return web_dir

if __name__ == '__main__':
	config_db(sys.argv)

