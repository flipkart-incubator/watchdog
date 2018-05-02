/* http://extjs.github.io/Connect/errorHandler.html */
/* this is a simple example server without any decent error handling.  it basically creates
   a server at port 3000 that enables you to hit the server and get the data back in json format.
   so you would hit it like this...

   curl http://localhost:3000/?url=http://cnn.com

   then the output would look like this...

{ 'Requested URL': 'http://www.cnn.com',
  'Page URL': 'http://www.cnn.com/',
  'Page Error': '',
  'Page Error Detail': '',
  'General Error Count': '0',
  'Page Error Count': '0',
  'Resource Error Count': '0',
  'Domain Change': '',
  'CName Change': '',
  PageLoad: '4489',
  'Copyright date': '2013',
  Websphere: '',
  '.NET': '',
  PHP: '',
  Janrain: '',
  Flash: '',
  Wordpress: '',
  CQ: '',
  'Operating System': '',
  'Webtrends Tagging': '',
  'Webtrends ID': '',
  'Google Analytics': '',
  'Pop-ups': '',
  'Video on Homepage': '',
  'Audio on Homepage': '',
  Downloads: '',
  Screensavers: '',
  Emoticons: '',
  Twitter: '',
  'Google Search': '',
  Facebook: '',
  Youtube: '',
  Netbiscuits: '',
  'Detected Apps': 'Disqus|jQuery|Modernizr|Nginx|Optimizely|Prototype|script.aculo.us' }


*/

var connect = require("connect");
var _       = require("underscore");
var exec    = require('child_process').exec;
var app = connect();

var regex = regexList();

connect()
    .use(connect.logger('dev'))
    .use(connect.bodyParser())
    .use(connect.query())
    .use(function(req, res, next) {
      var form = _.extend(req.query, req.body);
      if ( ! _.has(form, 'url') ) {
        next("expected a url param containing the detination to hit");
      }
      var job = "phantomjs phantalyzer.js " + form.url;
      /* setting the timeout here to 45 seconds */
      var child = exec(job, { 'maxBuffer' : 2000*1024, 'timeout' : 45000 },
        function (error, stdout, stderr) {
          console.log(stderr);

          var outputObj = {};
          //console.log(stdout);

	  for (var key in regex) {
	    var def = regex[key];
	    var exp = new RegExp(def.pattern, def.modifiers);
	    var match = stdout.match(exp);
	    var result = "";
	    //console.log("checking " + def.pattern + ", match=", match);
	    if ( match ) {
	      result = match[0];
	      //console.log('KEY=' + key);
	      if ( def.hit != undefined ) {
		result = def.hit;
		for (var k = 0; k < match.length; k++ ) {
		  result = result.replace('\{\{' + k + '\}\}', match[k]);
		}
	      }
	      result = result.replace('\{\{count\}\}', match.length);
	      //console.log('output=' + result);
	    } else {
	      if ( def.miss != undefined ) {
		result = def.miss;
	      }
	    }
            outputObj[key] = result;
          }

          console.log(outputObj);

          var jsonOut = JSON.stringify(outputObj);

          res.writeHead(200, {
            'Content-Length': jsonOut.length,
	   // 'Content-Type': 'text/plain'
	    'Content-Type': 'application/json'
	  });
          res.end(jsonOut);
        }
      );
    })
    .use(connect.errorHandler({ dumpExceptions: true }))
    .listen(3000);


function regexList() {
  var regexList = {
    "Requested URL" : {
        "pattern" : "^requestedUrl: ([^$]+?)$",
        "modifiers" : "m",
        "hit" : "{{1}}",
        "miss" : "report missing" 
    },
    "Page URL" : {
        "pattern" : "^pageUrl: ([^$]+?)$",
        "modifiers" : "m",
        "hit" : "{{1}}",
        "miss" : "miss" 
    },
    "Page Error" : {
        "pattern" : "^pageError: ([^$]+?)$",
        "modifiers" : "m",
        "hit" : "{{1}}",
        "miss" : "" 
    },
    "Page Error Detail" : {
        "pattern" : "^pageErrorDetail: ([^$]+?)$",
        "modifiers" : "m",
        "hit" : "{{1}}",
        "miss" : "" 
    },
    "General Error Count": {
        "pattern": "^error: ",
        "modifiers": "im",
        "hit" : "{{count}}",
        "miss" : "0"
    },
    "Page Error Count": {
        "pattern": "^pageError: ",
        "modifiers": "im",
        "hit" : "{{count}}",
        "miss" : "0"
    },
    "Resource Error Count": {
        "pattern": "^resourceError: ",
        "modifiers": "im",
        "hit" : "{{count}}",
        "miss" : "0"
    },
    "Domain Change" : {
        "pattern" : "^domainChange:",
        "modifiers" : "m",
        "hit" : "yes",
        "miss" : "" 
    },
    "CName Change" : {
        "pattern" : "^cnameDomainChange:",
        "modifiers" : "m",
        "hit" : "yes",
        "miss" : "" 
    },
   "PageLoad" : {
        "pattern" : "^pageLoadTimeMillis: (\\d+)",
        "modifiers" : "m",
        "hit" : "{{1}}",
        "miss" : "not found"
    },
    "Copyright date" : {
        "pattern": "©\\s*(\\d{4}(?:\\s*-\\s*\\d{4})?)",
        "modifiers": "i",
        "hit" : "{{1}}",
        "miss" : ""
    },  
    "Websphere": {
        "pattern": "^wappalyzerDetected: Java",
        "modifiers": "im",
        "hit" : "yes",
        "miss" : ""
    },
    ".NET": {
        "pattern": "^wappalyzerDetected: Microsoft ASP.NET",
        "modifiers": "mi",
        "hit" : "yes",
        "miss" : ""
    },
    "PHP": {
        "pattern": "^wappalyzerDetected: PHP",
        "modifiers": "mi",
        "hit" : "yes",
        "miss" : ""
    },
    "Janrain": {
        "pattern": "janrain",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Flash": {
        "pattern": "(<\\s*embed\\s+[^>]*\\.swf?|wappalyzerDetected: SWFObject)",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Wordpress": {
        "pattern": "^wappalyzerDetected: WordPress",
        "modifiers": "mi",
        "hit" : "yes",
        "miss" : ""
    },
    "CQ": {
        "pattern": "^wappalyzerDetected: Adobe CQ5",
        "modifiers" : "m",
        "hit" : "yes",
        "miss" : ""
    },
    "Operating System": {
        "pattern": "^wappalyzerDetected: (Unix|Centos|Redhat|Windows Server)",
        "modifiers": "mi",
        "hit" : "{{1}}",
        "miss" : ""
    },
    "Webtrends Tagging": {
        "pattern": "//statse.webtrendslive.com/([^/]+)",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Webtrends ID": {
        "pattern": "//statse.webtrendslive.com/([^/]+)",
        "modifiers": "i",
        "hit" : "{{1}}",
        "miss" : ""
    },
    "Google Analytics": {
        "patternx": "utmac=(UA-[-0-9]+)",
        "pattern": "['\"](UA-\\d+-\\d+)['\"]",
        "modifiers": "i",
        "hit" : "{{1}}",
        "miss" : ""
    },
    "Pop-ups": {
        "pattern": "window.open",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Video on Homepage": {
        "pattern": "\\.(wmv|mov|flv|mp4|ogg|webm)",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Audio on Homepage": {
        "pattern": "\\.(aac|m4a|mpeg|mp1|mp2|mp3|mpg|mpeg|oga|ogg|wav)",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Downloads": {
        "pattern": "href\\s*=\\s*['\"][^>]*downloads",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Screensavers": {
        "pattern": "href\\s*=\\s*['\"][^>]*screensavers",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Emoticons": {
        "pattern": "href\\s*=\\s*['\"][^>]*emoticons",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Twitter": {
        "pattern": "^resourceReceived: .*twitter\\.com.*$",
        "modifiers": "im",
        "hit" : "yes",
        "miss" : ""
    },
    "Google Search": {
        "pattern": "(//www\\.google\\.com/cse/cse\\.js|<gcse:search>)",
        "modifiers": "i",
        "hit" : "yes",
        "miss" : ""
    },
    "Facebook": {
        "pattern": "^resourceReceived: .*facebook\\.com.*$",
        "modifiers": "im",
        "hit" : "yes",
        "miss" : ""
    },
    "Youtube": {
        "pattern": "^resourceReceived: .*youtube\\.com.*$",
        "modifiers": "im",
        "hit" : "yes",
        "miss" : ""
    },
    "Netbiscuits" : {
        "pattern":"Netbiscuits",
        "modifiers" : "i",
        "hit"        : "yes",
        "false"      : ""
    },
    "Detected Apps" : {
        "pattern" : "^detectedApps: ([^$]*?)$",
        "modifiers" : "m",
        "hit"       : "{{1}}",
        "false"      : ""
    }
  };
  return regexList;
}
