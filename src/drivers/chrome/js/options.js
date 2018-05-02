document.addEventListener('DOMContentLoaded', function() {
	var d = document;

	var options = {
		opts: defaults,

		init: function() {
			options.load();

			d.getElementById('github'    ).addEventListener('click', function() { window.open(wappalyzer.config.githubURL);  });
			d.getElementById('twitter'   ).addEventListener('click', function() { window.open(wappalyzer.config.twitterURL); });
			d.getElementById('wappalyzer').addEventListener('click', function() { window.open(wappalyzer.config.websiteURL + '?pk_campaign=chrome&pk_kwd=options'); });

			d.getElementById('options-save').addEventListener('click', options.save);
		},

		load: function() {
			for ( option in options.opts ) {
				if ( value = localStorage[option] ) {
					options.opts[option] = value;
				}
			}

			if ( options.opts.autoAnalyzeHeaders === "0" || options.opts.autoAnalyzeHeaders === "1" ) {
				//Remove old stored option from localStorage because it's no longer needed. This can be entirely removed in future versions
				delete localStorage['autoAnalyzeHeaders'];
			}

			if ( parseInt(options.opts.upgradeMessage) ) {
				d.getElementById('option-upgrade-message').setAttribute('checked', 'checked');
			}

			if ( parseInt(options.opts.tracking) ) {
				d.getElementById('option-tracking').setAttribute('checked', 'checked');
			}
		},

		save: function() {
			options.opts.upgradeMessage     = d.getElementById('option-upgrade-message'     ).checked ? 1 : 0;
			options.opts.tracking           = d.getElementById('option-tracking'            ).checked ? 1 : 0;

			for ( option in options.opts ) {
				localStorage[option] = options.opts[option];
			}

			d.getElementById('options-saved').style.display = 'inline';

			setTimeout(function(){
				d.getElementById('options-saved').style.display = 'none';
			}, 2000);
		}
	};

	options.init();
});
