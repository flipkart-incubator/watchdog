var page = require('webpage').create();
system = require('system');

url = system.args[1];

page.open(url, function(status) {
  var title = page.evaluate(function() {
    return document.body;
  });
  title = JSON.stringify(title.outerHTML)
  console.log(title);
  phantom.exit();
});
