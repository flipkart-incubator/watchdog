var wappalyzer = require("./index");

var options={
  url : "http://codelanka.github.io/Presentation-Engines",
  hostname:"codelanka.github.io",
  debug:false
}

wappalyzer.detectFromUrl(options,function  (err,apps,appInfo) {
  console.log(err,apps,appInfo);
})