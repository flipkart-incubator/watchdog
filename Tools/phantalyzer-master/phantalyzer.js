/* the goal of this script is to open the page and spit out as much crap as possible so that
   you can grep over it later and derive information from it. */
var        Q = require('q');
var        S = require('string');
var        U = require('underscore');
var   system = require('system');
var       fs = require('fs'); //http://code.google.com/p/phantomjs/source/browse/test/fs-spec-01.js?r=c22dfdc576fccd20db53e11a92cb349aa3cd0b2b
//var   urlLib = require('url');

//var parsed = parseUri('http://wwww.hello.com/');
//console.log(JSON.stringify(parsed,null,2));
//phantom.exit();

var page = require('webpage').create();
var basePageReached = false;
var destinationError = false;

//var url = system.args[1];
var argMap = parseArgs().map;
var argV   = parseArgs().v;
var url = U.last(argV);

var headers = {};
var startTime = new Date().getTime();

/* you can pass any of these parameters in and they will override the 
  phantom defaults.  the format is --loadImages true */
var phantomPageProperties = {
  "javascriptEnabled" : true,
  "loadImages" : true,
  "localToRemoteUrlAccessEnabled" : true,
  "userAgent" : true,
  "userName" : true,
  "password" : true,
  "XSSAuditingEnabled" : true,
  "webSecurityEnabled" : true,
};

// defaults
page.settings.loadImages = true;
page.settings.webSecurityEnabled = false;
page.settings = U.extend(page.settings, U.pick(argMap, U.keys(phantomPageProperties)) );
console.log('settings', JSON.stringify(page.settings));

if ( U.has(argMap, "imageFile") ) {
  if ( ! argMap['imageFile'].match(/\.(jpg|jpeg|gif|png)$/i) ) {
    console.log('error: --imageFile ' + argMap['imageFile'] + ' must be jpeg, jpg, gif, or png');
    phantom.exit();
  }
}

var timeoutMs = 25000;

var timerId = setTimeout(function() {
  //console.log('closing page ' + url + ' due to timeout');
  console.log('pageError: timeout');
  page.close();
  phantom.exit();
}, timeoutMs);

page.onError = function(msg, trace) {
  console.log('pageError: ' + msg + ' trace=' + JSON.stringify(trace));
};

page.onResourceError = function(resourceError) {
  console.log('resourceError: ' + resourceError.url + ' errorCode=' + resourceError.errorCode + 
              ' errorString=' + resourceError.errorString);
};

var timerId = setTimeout(function() {
  console.log('error: page load timed out');
  page.close();
}, 30000);

function parseArgs() {
  var args = { map:{},v:[] };

  var argv = [];
  for ( var i = 1; i < system.args.length; i++ ) {
    if ( i < system.args.length - 1 && system.args[i].match(/^--.+/) ) {
      var argVal = system.args[i+1];
      if ( argVal == 'false' ) argVal = false;
      if ( argVal == 'true' ) argVal = true;
      args.map[system.args[i].substring(2)] = argVal;
      i++;
    } else {
      args.v.push(system.args[i]);
    }
  }
  return args;
}

page.onResourceRequested = function (request, requestController) {
  for ( var prop in request ) {
    if ( prop == 'headers' ) {
      var headers = request['headers'];
      for ( var k = 0; k < headers.length; k++ ) {
        console.log('resourceRequested.header.' + headers[k].name + ': ' + headers[k].value);
      }
    } else {
      console.log('resourceRequested.' + prop + ': ' + request[prop]);
    }
  }
  //console.log('resourceRequested: ', JSON.stringify(request, undefined, 2));

  //console.log("PAGE REQUEST", JSON.stringify(page, undefined, 2));
};

/**
 * Lambda to build a handler for the PhantomJS
 * resource received handler
 */
page.onResourceReceived = function(resource) {

  console.log('resourceReceived: ' + resource.url); 
  // we are trying to find the base page and determine
  // if the status code was successful
  if ( ! basePageReached ) {
    var isRedirect = U.indexOf([301, 302, 303, 307, 308], resource.status) >= 0;
    if ( ! isRedirect ) {
      basePageReached = true;
      console.log('pageHttpCode: ' + resource.status);
      console.log("pageUrl: " + resource.url);
      if ( resource.status < 200 || resource.status > 226 ) {
	console.log("pageError: " + resource.status);
        /*console.log("pageErrorDetail: " + JSON.sresource)); */
	destinationError = true;
      } else {
	// found the base page
	resolvedUrl = resource.url;  
	for (var i = 0; i < resource.headers.length; i++) {
	  //console.log('HEADER=' + resource.headers[i].name + ': ' + resource.headers[i].value);
	  console.log("resourceHeader: " + resource.url + ' name=' + resource.headers[i].name + 
	      ' value=' + resource.headers[i].value);
          headers[resource.headers[i].name] = resource.headers[i].value;
	}

        /* let's take a look at the domain requested and the path requested */
        try {
          var parsedReqUrl = parseUri(url);
          var parsedResUrl = parseUri(resolvedUrl);

          console.log('requestedUrlDomain: ' + parsedReqUrl.host);
          console.log('resolvedUrlDomain: ' + parsedResUrl.host);

          var toLowerCase = function(item, index) { return item.toLowerCase(); };
          var urlHostArr = U.map(parsedReqUrl.host.split(/\./), toLowerCase);
          var resHostArr = U.map(parsedResUrl.host.split(/\./), toLowerCase);

          console.log('urlHostDomain', urlHostArr);
          console.log('resHostDomain', resHostArr);

          var countryTld = false;
          if ( urlHostArr.length > 0 && resHostArr.length > 0 ) {
            var lastUrlToken = urlHostArr[urlHostArr.length - 1];
            var lastResToken = resHostArr[resHostArr.length - 1];
            if ( lastUrlToken == lastResToken && lastUrlToken.match(/^(?:AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BL|BM|BN|BO|BQ|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|EH|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MF|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|UM|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)$/i) ) {
              countryTld = true;
              urlHostArr.pop();
              resHostArr.pop();
            }

            /* let's remove www from the urls. we don't want to report a cname change if it's just www */
            if ( urlHostArr.slice(0,1) == 'www' ) {
              urlHostArr = urlHostArr.slice(1);
            }
            if ( resHostArr.slice(0,1) == 'www' ) {
              resHostArr = resHostArr.slice(1);
            }
           

            /* let's check the last two domain tokens.  if they used a TLD like coca-cola.fr then we will
               only check for the first one. */
            if ( urlHostArr.pop() != resHostArr.pop() ||
                 (countryTld == false && urlHostArr.pop() != resHostArr.pop()) ) {
              console.log('domainChange: true');
            } else {
              /* now let's check cname tokens */
              if ( urlHostArr.length != resHostArr.length ) {
                console.log('cnameDomainChange: true');
              } else {
                while ( urlHostArr.length > 0 ) {
                  if ( urlHostArr.pop() != resHostArr.pop() ) {
                    console.log('cnameDomainChange: true');
                    break;
                  }
                }
              }
            }
          }
        } catch (error) {
          console.log(error);
        }
      }
    } else {
      console.log("page.redirect.code: " + resource.status);
    }
  }
}

console.log("requestedUrl: " + url);

page.open(url, function (status) {
  //Page is loaded!
  clearTimeout(timerId);
  //console.log('pageStatus: ' + status);
  //console.log('error: ' + destinationError);
  //console.log('page loaded. status=' + resource + ' for url ' + url);
  //console.log(page.content);
  //var cleanContent = fixNoScript(page.content);
  var pageContent = page.content;
  pageContent = page.content.replace(/\s*/, ' ');
  console.log('pageContent: ' + pageContent);

  /* ok, let's inject the wappalyzer stuff */
  page.injectJs('wappalyzer/wappalyzer.js');
  page.injectJs('wappalyzer/apps.js');
  page.injectJs('wappalyzer/driver.js');

  var detectedApps = page.evaluate(function (url, headers, pageContent) {

    pageContent = document.getElementsByTagName('html')[0].innerHTML;
 
    // the env property of wappalyzer is elusive because with phantomjs we
    // don't yet have the ability to get the source of all of the scripts
    // that are loaded without doing the work of going out separately to get them.
    // we can do that later but in the mean time we are going to pass in the source for all
    // of the script elements.

    var env = [];
    for(var env_var in window) { 
      if ( window.hasOwnProperty(env_var)) {
        env.push(env_var);
      } 
    }
    //console.log('ENV VARS=' + env);
    wappalyzer.analyze(url, url, {
      html: pageContent,
      headers: headers,
      env: env
    });

    //console.log('HTML=' + document.getElementsByTagName('html')[0].innerHTML);
    console.log('info: ' + url + '] finished with eval on wappalyzer');

    var apps = [];
    wappalyzer.detected[url].map(function(app) {
      if ( wappalyzer.apps[app] ) {
        //var cats = wappalyer.apps[app].cats;
        apps.push(app);
      }
    });

    // the return value has to be a primitive because
    // this shit is completely sandboxed.
    // i tried to JSON.stringify this but some of the sites
    // have hijacked stringify (prototype i think) and jacked it
    // up.  so i'm going to just do a join.
    return apps.join('|');
        
  }, url, headers, pageContent);

  console.log('detectedApps: ' + detectedApps);

  // so the return value here is a pipe separated string of apps that are
  // matching for the page.  let's go ahead and cram them back into the destination
  // so that when we write it back out we will have that info.
  var detected = detectedApps.split('|');
  for ( var i = 0; i < detected.length; i++ ) {
    console.log('wappalyzerDetected: ' + detected[i]);
  }

  console.log('pageLoadTimeMillis: ' + (new Date().getTime() - startTime));

  U.each(phantom.cookies, function(cookie, index) {
    console.log("cookie: " + JSON.stringify(cookie));
  });
  console.log('cookieDomains: ' + U.chain(phantom.cookies).pluck("domain").unique().value().join(','));

  if ( U.has(argMap, 'imageFile') ) {
    try {
      window.setTimeout((function() {
        page.render(argMap['imageFile']);
        console.log('screenShotPath: ' + argMap['imageFile']);
        page.close();
        phantom.exit();
      }), 5000);
    } catch (e) {
      console.log('error saving image', e);
    }
  } else {
    page.close();
    phantom.exit();
  }
});

/**
 * There is a PhantomJS but that seems to 
 * escape the entities in the noscript tags.
 * This of course is where a lot of the analytics
 * sequences are found.  This function will return
 * them to their rightful form.
 */
function fixNoScript(content) {
  var noscript = /<\s*noscript\s*>([^<]+)<\s*\/\s*noscript\s*>/ig;
  var matches = content.match(noscript);
  if ( ! matches ) {
    return content;
  }

  for ( var i = 0; i < matches.length; i++ ) {
    var decoded = S(matches[i]).decodeHTMLEntities().s;
    var index = content.indexOf(matches[i]);
    content = content.substring(0, index) + 
              decoded +
              content.substring(index + matches[i].length);
  }
  return content;
}

function parseUri (str) {

  var options = {
    strictMode: false,
    key: ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
    q:   {
      name:   "queryKey",
      parser: /(?:^|&)([^&=]*)=?([^&]*)/g
    },
    parser: {
      strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/,
      loose:  /^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/
    }
  };

  var	o   = options,
	m   = o.parser[o.strictMode ? "strict" : "loose"].exec(str),
	uri = {},
	i   = 14;

  while (i--) uri[o.key[i]] = m[i] || "";

  uri[o.q.name] = {};
  uri[o.key[12]].replace(o.q.parser, function ($0, $1, $2) {
    if ($1) uri[o.q.name][$1] = $2;
  });

  return uri;
};
