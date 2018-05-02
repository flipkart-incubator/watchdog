### Overview ###
Phantalyzer is a [PhantomJS](http://phantomjs.org/) (headless Webkit browser bot) based tool that leverages [Wappalyzer](http://wappalyzer.com/) (browser plugin) to detect software in use across a large number of sites.  Wappalyzer is a browser plug-in so it's original design is to provide feedback from within the browser.  My intent here is to enable analysis and reporting for a large numbers of sites.  An example of this would be a report that indicates which sites are using Flash (and may need to be converted), which are not using proper analytics tags, etc.

### Installation ###

In order to use Phantalyzer, you must install PhantomJS.  It is also important to note that PhantomJS and Node.js look very similar but they are completely different platforms.  In this project, we use PhantomJS to handle the web page loading but Node.js to handle everything else such as analysis of the data.

### Details and Usage ###

At the core of the system is a js file called phantalyzer.js.  This file is a PhantomJS script that will open a headless Webkit browser, navigate to the site, and essentially write everything it sees to standard output.  This output also includes output from the Wappalyzer scripts.  You can run this by doing the following.

phantomjs phantalyzer.js http://www.cnn.com

All of the output HTML from CNN would be piped to standard out as well as headers, resources requested, and last but not least, the apps detected by the Wawppalyzer.  Here is an example of the information written out from Wappalyzer.

    detectedApps: Disqus|jQuery|Modernizr|Nginx|Optimizely|Prototype|script.aculo.us
    wappalyzerDetected: Disqus
    wappalyzerDetected: jQuery
    wappalyzerDetected: Modernizr
    wappalyzerDetected: Nginx
    wappalyzerDetected: Optimizely
    wappalyzerDetected: Prototype
    wappalyzerDetected: script.aculo.us

Here is a list of all of the current information presented by the script.  Each field is on a new line and has a colon afterwards.

    detectedApps
    error
    info
    page.redirect.code
    pageContent
    pageError
    pageError
    pageHttpCode
    pageLoadTimeMillis
    pageUrl
    requestedUrl
    requestedUrlDomain
    resolvedUrlDomain
    resourceError
    resourceHeader
    resourceReceived
    resourceRequested
    screenShotPath
    wappalyzerDetected

phantalyzer.js can accept a number of parameters.  Many of these are just pass through to PhantomJS.  Here is a list of the parameters that are take from PhantomJS and their defaults.

    javascriptEnabled = true
    loadImages = true
    localToRemoteUrlAccessEnabled = true
    userAgent = true
    userName = true
    password = true
    XSSAuditingEnabled = true
    webSecurityEnabled = true

phantalyzer.js also accepts an imageFile parameter so enables you to indicate that an screen shot should be captured and written to disk.  You can do this as follows.

    phantalyzer.js --imageFile ~/tmp/cnn.png --webSecurityEnabled false http://cnn.com

If you are not planning to take screen shots or dod analysis such as web analytics where images need to be loaded, then you should consider setting loadImages to false to speed things up.

    phantalyzer.js --loadImages false http://cnn.com

### Runing over multiple sites ###

If you goal is to load a bunch of sites and generate reports then you will want to look at csv2phant.js.  This program will load in a CSV file full of site info and run phantalyzer.js for each site.  You can then use phant2csv.js to scoop up that data and get it back into a spreadsheet.  There is a critical parameter called urlColumn that will enable you to specify the CSV column name that the program should use as a URL for PhantomJS.

    node csv2phant.js --dataDir ~/tmp/phantalyzerData --csvFile  listOfSites.csv  --imageFormat png --urlColumn URL

csv2phant.js will run PhantomJS over each file in your CSV and dump a text report and image out to the data directory you specified.  phant2csv.js will process these and generate a spreadsheet with rollup data.

    node phant2csv.js --dataDir ~/tmp/phantalyzerData --csvFile  listofSites.csv --regexFile regexlist.json --urlColumn URL

The file regexlist.json is a list of regular expressions that will enable you to pull out key information from the output files and turn them into columns in the output.  This is of course customizable.

### server.js ###

This was not originally written to act as a server but because that is the logical progression, I wrote a small connect.js based server that illustrates how you could conceivably run this.  If you run the server like so....

```
node server.js
```

Then you would be able to curl to it like this...

```
curl http://localhost:3000/?url=http://cnn.com
```

And the result would look like this...

```
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
```

Keep in mind that server.js is a starting point for you to write your own server.  I would also recommend using something like Express.js instead of connect.js.  I like connect because it is so lightweight and I just wanted to do something simple.

### The following is a list of apps the Wappalyzer detects ###

```
1C-Bitrix
1und1
2zProject
AddThis
AdobeCQ5
AdobeGoLive
AdvancedWebStats
Alloy
Ametys
Amiro.CMS
AMPcms
AOLserver
Apache
ApacheJSPWiki
ApacheTomcat
ApacheTrafficServer
ArcForum
ATGWebCommerce
AtlassianConfluence
AtlassianJira
AWStats
Backbone.js
Banshee
BIGACE
BigDump
Bigware
Blip.tv
Blogger
BrowserCMS
Bugzilla
BurningBoard
BusinessCatalyst
CakePHP
Cargo
CentOS
CFML
Chameleon
Chamilo
Chartbeat
Cherokee
CKEditor
ClickHeat
ClickTale
Clicky
CMSMadeSimple
CO2Stats
CodeIgniter
CommerceServer
comScore
Concrete5
Connect
Contao
Contenido
Contens
ConversionLab
Coppermine
Cosmoshop
Cotonti
CouchDB
cPanel
CPGDragonfly
CrazyEgg
CSCart
CubeCart
Cufon
d3
Dancer
DanneoCMS
dashCommerce
DataLifeEngine
DavidWebbox
Debian
DedeCMS
Demandware
DHTMLX
DirectAdmin
Disqus
Django
DjangoCMS
Dojo
Dokeos
DokuWiki
DotNetNuke
Doxygen
DreamWeaver
Drupal
DrupalCommerce
Dynamicweb
e107
Ecodoo
EPiServer
Exhibit
Express
ExpressionEngine
ExtJS
eZPublish
FactFinder
FASTESP
FASTSearchforSharePoint
FlexCMP
FluxBB
Flyspray
FreeBSD
FrontPage
FWP
Gallery
Gambio
Gauges
Gentoo
GetSatisfaction
GetSimpleCMS
GoogleAnalytics
GoogleAppEngine
GoogleFontAPI
GoogleMaps
GoogleSites
GoStats
GraffitiCMS
Gravatar
GravityInsights
Handlebars
Hiawatha
Highcharts
HotaruCMS
Hybris
IBMHTTPServer
IBMWebSpherePortal
IBMWebSphereCommerce
IIS
ImpressPages
Indexhibit
InstantCMS
Intershop
IPB
iWeb
Jalios
Java
JavascriptInfovisToolkit
Jo
JobberBase
Joomla
jqPlot
jQTouch
jQuery
jQueryMobile
jQuerySparklines
jQueryUI
JSCharts
JTLShop
K2
Kampyle
KenticoCMS
Koego
Kohana
KolibriCMS
Koobi
LEPTON
Liferay
LightMon
lighttpd
LimeSurvey
LiveJournal
LotusDomino
Magento
Mambo
MantisBT
MaxSiteCMS
MediaWiki
Meebo
MicrosoftASP.NET
MicrosoftSharePoint
MiniBB
Mint
Mixpanel
MochiKit
Modernizr
MODx
Mojolicious
Mollom
MondoMedia
Mongrel
Moodle
Moogo
MooTools
MovableType
Mustache
MyBB
MyBlogLog
Mynetcap
Nedstat
NetBiscuits
Netmonitor
Nginx
node.js
NOIX
nopCommerce
OneStat
OpenCart
openEngine
OpenGSE
OpenLayers
OpenNemas
OpenWebAnalytics
Optimizely
OracleRecommendationsOnDemand
osCommerce
osCSS
OXIDeShop
PANSITE
papayaCMS
Parse.ly
Percussion
Perl
PHP
phpBB
phpCMS
phpDocumentor
PHP-Fusion
phpMyAdmin
PHP-Nuke
phpPgAdmin
Piwik
Plentymarkets
Plesk
Pligg
Plone
Plura
Posterous
Powergap
Prestashop
Prototype
Protovis
punBB
Python
Quantcast
Quick.Cart
Raphael
RBSChange
ReallyCMS
reCAPTCHA
RedHat
Reddit
Redmine
Reinvigorate
RequireJS
RoundCube
Ruby
S.Builder
s9y
script.aculo.us
SenchaTouch
Seoshop
ShareThis
Shopify
Shopware
sIFR
SiteMeter
SiteCatalyst
SiteEdit
Smartstore
SMF
sNews
Snoobi
SOBI2
SoundManager
SPDY
SPIP
SQLBuddy
Squarespace
SquizMatrix
StatCounter
StoreSystems
SWFObject
swift.engine
Swiftlet
TextpatternCMS
three.js
TikiWikiCMSGroupware
Timeplot
TinyMCE
TomatoCart
Trac
Tumblr
TwilightCMS
TwitterBootstrap
Typekit
TypePad
TYPO3
Ubercart
Ubuntu
Umbraco
Underscore.js
UNIX
UserRules
UserVoice
Vanilla
Varnish
vBulletin
viennaCMS
Vignette
Vimeo
VirtueMart
VisualPath
VIVVO
Vox
VP-ASP
W3Counter
WebOptimizer
webEdition
WebGUI
WebPublisher
Websale
WebsiteBaker
Webtrekk
Webtrends
Weebly
WikkaWiki
WindowsServer
Wink
WolfCMS
Woopra
WordPress
Xajax
Xanario
XenForo
XiTi
XMB
XOOPS
xtCommerce
xui
YaBB
Yahoo!WebAnalytics
Yandex.Metrika
YouTube
YUIDoc
YUI
ZenCart
Zend
Zepto
Zinnia
```

### Task List ###
- [ ] Add instructions on how to run this on the server.



