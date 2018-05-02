<?php

require('WappalyzerException.php');
require('Wappalyzer.php');

try {
	if ( php_sapi_name() !== 'cli' ) {
		exit('Run me from the command line');
	}

	$url = !empty($argv[1]) ? $argv[1] : '';

	if ( !$url ) {
		echo "Usage: php {$argv[0]} <url>\n";

		exit(0);
	}

	$wappalyzer = new Wappalyzer($url);

	$detectedApps = $wappalyzer->analyze();

	if ( $detectedApps ) {
		foreach ( $detectedApps as $detectedApp => $data ) {
			echo $detectedApp . ', ' . $data->version . ', ', $data->confidence . '%, ', implode(', ', $data->categories) . "\n";
		}
	} else {
		echo "No applications detected\n";
	}

	exit(0);
} catch ( Exception $e ) {
	echo $e->getMessage() . "\n";

	exit(1);
}
