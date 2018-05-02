document.addEventListener('DOMContentLoaded', function() {
	var
		i, value,
		d     = document
		nodes = d.getElementsByTagName('*')
		;

	for ( i = 0; i < nodes.length; i ++ ) {
		if ( attr = nodes[i].dataset.i18n ) {
			nodes[i].innerHTML = chrome.i18n.getMessage(attr);
		}
	}
});
