# Wappalyzer

## Install

Install wappalyzer from NPM with:

```bash
npm install wappalyzer
```
## Quickstart

```javascript
// load in the lib
var wappalyzer = require("wappalyzer");

// set our options
var options={

  url : "http://codelanka.github.io/Presentation-Engines",
  hostname:"codelanka.github.io",
  debug:false

}

// detect from the url directly, library will make a request
wappalyzer.detectFromUrl(options,function  (err,apps,appInfo) {

  // output for the test
  console.dir(apps);
  console.dir(appInfo);

})

// sample data
var data = {

  url: options.url,
  headers: {

    test: 1

  },
  html: '<p>HTML CONTENT OF PAGE HERE</p>'

};

// detect from content you have already
wappalyzer.detectFromHTML(options,function  (err,apps,appInfo) {

  // output for the test
  console.dir(apps);
  console.log(appInfo);

})
```
### Output from QuickStart

```javascript

// Apps
[ 
  'CloudFlare',
  'Font Awesome',
  'Google Maps',
  'Modernizr',
  'Nginx',
  'RequireJS',
  'jQuery' 
]

// Detailed info on links
{ 
  CloudFlare: { 
    app: 'CloudFlare',
    confidence: { 'headers Server /cloudflare/i': 100 },
    confidenceTotal: 100,
    detected: true,
    excludes: [],
    version: '',
    versions: [] 
  },
  'Font Awesome': { 
    app: 'Font Awesome',
    confidence: { 'html /<link[^>]* href=[^>]+font-awesome(?:\.min)?\.css/i': 100 },
    confidenceTotal: 100,
    detected: true,
    excludes: [],
    version: '',
    versions: [] 
  },
  'Google Maps': { 
    app: 'Google Maps',
    confidence: { 'script ///maps.googleapis.com/maps/api/js/i': 100 },
    confidenceTotal: 100,
    detected: true,
    excludes: [],
    version: '',
    versions: [] 
  },
  'Modernizr': { 
    app: 'Modernizr',
    confidence: { 'script /modernizr(?:-([\d.]*[\d]))?.*\.js/i': 100 },
    confidenceTotal: 100,
    detected: true,
    excludes: [],
    version: '2.6.2',
    versions: [ '2.6.2' ] 
  },
  'Nginx': { 
    app: 'Nginx',
    confidence: { 'headers Server /nginx(?:/([\d.]+))?/i': 100 },
    confidenceTotal: 100,
    detected: true,
    excludes: [],
    version: '',
    versions: [] 
  },
  'RequireJS': { 
    app: 'RequireJS',
    confidence: { 'script /require.*\.js/i': 100 },
    confidenceTotal: 100,
    detected: true,
    excludes: [],
    version: '',
    versions: [] 
  },
  'jQuery': { 
    app: 'jQuery',
    confidence: 
    { 'script //([\d.]+)/jquery(\.min)?\.js/i': 100,
    'script /jquery.*\.js/i': 100 },
    confidenceTotal: 100,
    detected: true,
    excludes: [],
    version: '1.10.1',
    versions: [ '1.10.1' ] 
  } 
}
```
## Credits

### Wappalyzer Author - Elbert Alias

[Wappalyzer](https://wappalyzer.com/) is a
[cross-platform](https://github.com/AliasIO/Wappalyzer/wiki/Drivers) utility that uncovers the
technologies used on websites.  It detects
[content management systems](https://wappalyzer.com/categories/cms),
[eCommerce platforms](https://wappalyzer.com/categories/ecommerce),
[web servers](https://wappalyzer.com/categories/web-servers),
[JavaScript frameworks](https://wappalyzer.com/categories/javascript-frameworks),
[analytics tools](https://wappalyzer.com/categories/analytics) and
[many more](https://wappalyzer.com/applications).

Refer to the [wiki](https://github.com/AliasIO/Wappalyzer/wiki) for
[screenshots](https://github.com/AliasIO/Wappalyzer/wiki/Screenshots), information on how to
[contribute](https://github.com/AliasIO/Wappalyzer/wiki/Contributing) and
[more](https://github.com/AliasIO/Wappalyzer/wiki/_pages).

### NPM Module

* [Pasindu De Silva](https://github.com/pasindud) - Initial version with tests
* [Johann du Toit](http://johanndutoit.net) from [Passmarked](http://passmarked.com) - Updated to support just passing data and helped publish to NPMJS

## License

*Licensed under the [GPL](https://github.com/AliasIO/Wappalyzer/blob/master/LICENSE).*

## Donations

Donate Bitcoin: 16gb4uGDAjaeRJwKVmKr2EXa8x2fmvT8EQ - *Thanks!*

![QR Code](https://wappalyzer.com/sites/default/themes/wappalyzer/images/bitcoinqrcode.png)
