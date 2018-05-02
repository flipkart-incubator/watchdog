'use strict';

var request = require('request');
var fs = require('fs');
var path = require('path');

/**
* Does the actual detection with information passed
**/
exports.detect = function(options, data, cb) {

	// run the wrapper function that will
	// trigger the actual library to run
	runWrappalyer(options, data, cb);

};

/**
* Wraps the detect method, just kept to reuse old method names
* and not break anything. Although this was just stubbed out.
**/
exports.detectFromHTML = function(options, data, cb) {

	// run the detect method
	exports.detect(options, data, cb);

};

/**
* Do a actual request for the body & headers, then
* run through detection
**/ 
exports.detectFromUrl = function(options, cb) {

	// ensure options and url were
	if(!options || !options.url) {

		// send back a error ...
		cb(new Error("\"url\" is a required option to run"
			+ " wappalyzer and get the page content"))

	} else {

		// local variables to
		var url = options.url;

		// get the body content from the url
		getHTMLFromUrl(url, function(err, data) {

			// check for error or if we got no data back
			if (err || data === null) {

				// handle the error and don't do anything else ..
				cb(err, null);

			} else {

				// run actual detection
				exports.detect(options, data, cb);

			}
		
		});

	}
};

function getHTMLFromUrl(url, cb) {
	request(url, function(error, response, body) {
		if (!error && response.statusCode == 200) {
			var data = {
				html: body,
				url: url,
				headers: response
			};
			cb(null, data);
		} else {
			cb(error, null);
		}
	});
}

function getAppsJson(cb) {

	// depending on evironment select a direction to the path
	var appsFileStr = path.resolve(__dirname, './apps.json');

	// handle the environment variable if it's there
	if(process.env.NODE_ENV == 'testing') {

		// set the apps.json to testing stage
		appsFileStr = path.resolve(__dirname, '../../apps.json');

	}

	// read in the file
	fs.readFile(appsFileStr, 'utf8', function(err, data) {
		if (err) throw err;
		return cb(null, JSON.parse(data));
	});
}

function runWrappalyer(options, data, cb) {
	var debug = options.debug || false;

	// according to environment check it
	var wappalyzer = null;

	// change depending on the environment
	if( process.env.NODE_ENV == 'testing' ) {

		wappalyzer = require('../../wappalyzer').wappalyzer;

	} else {

		wappalyzer = require('./wappalyzer').wappalyzer;

	}

	getAppsJson(function(err, apps) {
		var w = wappalyzer;
		w.driver = {
			log: function(args) {
				if (debug) {
					console.log(args.message);
				}
			},

			init: function() {
				w.categories = apps.categories;
				w.apps = apps.apps;
			},
			displayApps: function() {
				var app, url = Object.keys(w.detected)[0];
				var detectedApps = [];

				for (app in w.detected[url]) {
					detectedApps.push(app);

					if (debug) {
						console.log(app);
					}
				}
				cb(null, detectedApps, w.detected[url]);
			}
		};
		w.init();
		w.detected = [];
		w.analyze(options.hostname, options.url, data);
	});
}
