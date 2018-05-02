<?php

/*	author: Shubham Bansal
	employee id: 91524*/
?>

<?php
if (isset($_SERVER['HTTP_ORIGIN'])) {
    //header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
    header("Access-Control-Allow-Origin: *");
    header('Access-Control-Allow-Credentials: true');
    header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
}

$type = $_REQUEST['type'];
$repo = $_REQUEST['repo'];
$level = $_REQUEST['level'];
$count = $_REQUEST['count'];
$category = $_REQUEST['category'];
$input_ip = $_REQUEST['ip'];
$vul = $_REQUEST['vul'];

$client = new MongoClient();
$db = $client->config;
$collection = $db->internal;

$pp = $collection->findOne();
$scale_high_vul_repo = $pp["SCALE_HIGH_VUL_REPO"];
$scale_critical_vul_cve_internal = $pp["SCALE_CRITICAL_VUL_CVE_INTERNAL"];
$scale_high_vul_cve_internal = $pp["SCALE_HIGH_VUL_CVE_INTERNAL"];
$scale_medium_vul_cve_internal = $pp["SCALE_MEDIUM_VUL_CVE_INTERNAL"];

$scale_critical_vul_cve_external = $pp["SCALE_CRITICAL_VUL_CVE_EXTERNAL"];
$scale_high_vul_cve_external = $pp["SCALE_HIGH_VUL_CVE_EXTERNAL"];
$scale_medium_vul_cve_external = $pp["SCALE_MEDIUM_VUL_CVE_EXTERNAL"];

$client = new MongoClient();

function perform_unique_source( &$unique_high_vul_source , $repos_source , $critical_high)
{
	foreach ($repos_source as $repo_source) 
	{
		if( $repo_source["TotalCount"][$critical_high] == 0)
			continue;
		$name = $repo_source["Categories"];
		foreach ($name as $cat) 
		{
			if($cat["Count"][$critical_high] - $cat["false_count"][$critical_high] <= 0)
				continue;

			foreach($cat["Files"] as $a_file)
			{
				if( $a_file["false_positive"] != "0" )
					continue;
				if($a_file["level"] == $critical_high)
				{
					$size = sizeof($unique_high_vul_source);
					$i = 0;
					for ($i=0; $i < $size; $i += 1) { 
						if($unique_high_vul_source[$i]["name"] == $cat["Name"])
						{
							$size_unique_vul_source = sizeof($unique_high_vul_source[$i]["repos"]);
							$kk = 0;
							for ($kk=0; $kk < $size_unique_vul_source; $kk++) { 
								if($unique_high_vul_source[$i]["repos"][$kk]["name"] == $repo_source["RepoName"])
									break;
							}
							if($kk == $size_unique_vul_source)
								array_push( $unique_high_vul_source[$i]["repos"] , array("name" => $repo_source["RepoName"]));
							break;
						
						}
					}
					if($i == $size)
					{
						$temp = array("name" => $repo_source["RepoName"]);
						$document = array("name" => $cat["Name"],"repos" => array($temp));
						array_push($unique_high_vul_source, $document);             
						// [[name => <category_name> , repos => [<repo1>,<repo2>...]]...]	
					
					}
				}
			}
		}
	}
}

function find_unique_vul_external( &$unique_cve , $tech , $key , $value , $CVE)
{
	$size = sizeof($unique_cve);
	$i = 0;
	for ($i=0; $i < $size; $i++) { 
		if($unique_cve[$i]["cve"] == $CVE["id"])
		{
			$temp = array("ip" => $tech["ip"] , "domain" => $tech["domain"]);
			array_push( $unique_cve[$i]["ips"] , $temp);
			break;
		}
	}
	if( $i == $size)
	{
		$x = array();
		$temp = array("ip" => $tech["ip"] , "domain" => $tech["domain"]);
		array_push($x, $temp);
		$document = array("cve" => $CVE["id"] ,"cvss" => $CVE["cvss"] , "technology" => $key , "version" => $value["version"] , "ips" => $x);

		array_push($unique_cve , $document);
	}
}

function perform_unique_cve( &$unique_cve , $dep , $a_vul , $name)
{
	$size_unique_cve = sizeof($unique_cve);
	$i = 0;
	for($i = 0 ; $i < $size_unique_cve ; $i++)
	{
		if($unique_cve[$i]["cve"] == $name)
		{
			$size = sizeof($unique_cve[$i]["repos"]);
			$j = 0;
			for ($j=0; $j < $size; $j++) { 
				if($unique_cve[$i]["repos"][$j]["name"] == $dep["repository_name"])
				{
			//		array_push($unique_cve[$i]["repos"][$j]["dependencies"], $dep["dependency"]);
					$unique_cve[$i]["repos"][$j]["dependencies"] = $unique_cve[$i]["repos"][$j]["dependencies"]." , ".$dep["dependency"];
					break;
				}
			}
			if( $j == $size)
			{
		//		$temp_dep = array($dep["dependency"]);
		//		$temp = array("name" => $dep["repository_name"] , "dependencies" => $temp_dep);
				$temp = array("name" => $dep["repository_name"] , "dependencies" => $dep["dependency"]);
				array_push($unique_cve[$i]["repos"], $temp); 
			}
			break;
		}
	}
	if( $i == $size_unique_cve){
		$temp_dep = array($dep["dependency"]);
//		$temp = array("name" => $dep["repository_name"] , "dependencies" => $temp_dep);
		$temp = array("name" => $dep["repository_name"] , "dependencies" => $dep["dependency"]);
		$x = array();
		array_push($x, $temp);

		$temp = array("cve" => $name,"cvss_score" =>$a_vul["cvss_score"], "repos" => $x);
		array_push($unique_cve, $temp);
	}
}

function find_top3($most_used)
{
	$top3 = array();
	$size = sizeof($most_used);
	if($size ==1)
		return $most_used;
	else if($size == 2)
	{
		if($most_used[0]["value"] < $most_used[1]["value"])
		{
			array_push($top3, $most_used[1]);
			array_push($top3, $most_used[0]);
			return $top3;
		}
		else
			return $most_used;
	}
	else
	{
		$temp = array("name" => " " , "value" => 0);
		array_push($top3, $temp);
		array_push($top3, $temp);
		array_push($top3, $temp);

		$size = sizeof($most_used);
		$i = 0;
		for ($i=0; $i < $size; $i++) { 
			if($most_used[$i]["value"] > $top3[0]["value"])
			{
				$top3[2] = $top3[1];
				$top3[1] = $top3[0];
				$top3[0] = $most_used[$i];
			}
			else if($most_used[$i]["value"] > $top3[1]["value"])
			{
				$top3[2] = $top3[1];
				$top3[1] = $most_used[$i];
			}
			else if($most_used[$i]["value"] > $top3[2]["value"])
			{
				$top3[2] = $most_used[$i];
			}
		}
		return $top3;
	}
}

function correct_ip($ip)
{
	$len = strlen($ip);
        $i = 0;
        for( $i = 0 ; $i < $len ; $i = $i + 1 )
        {
        	if ($ip[$i] == "-")
                $ip[$i] = ".";
        }
	return $ip;
}

function find_highest_cvss_internal($name)
{
	$client = new MongoClient();
	$db = $client->config;
	$collection = $db->internal;
	$db = $collection->findOne();
	$db = $db["DATABASE"];
	$db = $client->$db;

	$collection = $db->dependency_checker;
	$highest_cvss = 0;
	$a_repo = $collection -> find(array("repository_name" => $name));
	
	foreach ($a_repo as $a_dep) {
		if( $a_dep["false_positive"] != "0")
			continue;
		if(floatval($a_dep["highest_cvss"]) >= $highest_cvss)
			$highest_cvss = floatval($a_dep["highest_cvss"]);		
	}
	return $highest_cvss;
}

if($type == "sendMail")
{
	$recipients = $_POST["recipient"];
	$repoName = $_POST["repoName"];
//	echo $repoName." ".$recipients;
	$cmd = "python sendMail.py ".$repoName." ".$recipients;
//	foreach( $send_to as $xx)
//		echo $xx;
//	echo json_encode($send_to);
//	echo $cmd;
	exec($cmd,$output);
	echo $output;
}
else if($type == "external")
{
	$db = $client->config;
	$collection = $db->external;
	$db = $collection->findOne();
	$db = $db["DATABASE"];
	$db = $client->$db;

	
	if($category == "falsePositiveTech" or $category == "falsePositiveTechHistory")
	{
		if( $category == "falsePositiveTechHistory")
		{
			$db = $client->config;
			$collection = $db->external;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

		$ip = $_POST["ip"];
		$technologies = $_POST["technologies"];
		$date_data = $_POST["date"];
		$collection = $db->technologies;
		
		$val = $collection->findOne(array("ip" => $ip));
		foreach( $technologies as $a_technology)
		{	
			$flag = $val[$a_technology]["false_positive"];
			echo "before ".$a_technology." ".$flag;
			if($flag == "0")
				$flag = $date_data;
			else
				$flag = "0";
			$temp = $val[$a_technology];
			$temp["false_positive"] = $flag;
			$collection->update(array('ip'=>$ip),array('$set' => array( $a_technology => $temp ) ));
		//	$temp = $collection->findOne(array("ip" => $ip));
		//	echo "after ".$a_technology." ".$temp[$a_technology]["false_positive"];
		}
	}
	else if($category == "falsePositivePort" or $category == "falsePositivePortHistory")
	{
		if( $category == "falsePositivePortHistory")
		{
			$db = $client->config;
			$collection = $db->external;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

		$ip = $_POST["ip"];
		$services = $_POST["services"];
		$date_data = $_POST["date"];
		$collection = $db->services;
		$val = $collection->findOne(array("ip" => $ip));
		foreach( $services as $a_service)
		{	
			$flag = $val[$a_service]["false_positive"];
			echo "before ".$a_service." ".$flag;
			if($flag == "0")
				$flag = $date_data;
			else
				$flag = "0";
			$temp = $val[$a_service];
			$temp["false_positive"] = $flag;
			$collection->update(array('ip'=>$ip),array('$set' => array( $a_service => $temp ) ));
		//	$temp = $collection->findOne(array("ip" => $ip));
		//	echo "after ".$a_service." ".$temp[$a_service]["false_positive"];
		}
	}
	else if($category == "firstTimeInput")
	{
		$data = $_POST["firstTimeInput"];
		echo json_encode($data);

		
		foreach($data as $a_input){
			$db = $client->config;
			$collection = $db->external;
			$db = $collection->findOne();
			$db = $db["DATABASE"];
			$db = $client->$db;

			$collection = $db->ipInventory;
			$val = $collection->findOne(array("ip" => $a_input["ip"]));
			if($val == null or $val == NULL or $val == ""){ 
				$collection->insert($a_input);
			}
			else if( $a_input["domain"] != "" and ($val["domain"] == "" or $val["domain"] == null or $val["domain"] == NULL) )
				$collection->update( array("ip" => $a_input["ip"]) , array("$set" => array("domain" => $a_input["domain"])));
		}
	}
	else if($category == "checkSelfServeInput")
	{
		$db = $client->config;
		$collection = $db->external;
		$db = $collection->findOne();
		$db = $db["SELF_SERVE_DATABASE"];
		$db = $client->$db;
	
	//	$data = $_POST["checkSelfServeInput"];
	//	echo json_encode($data);

		$collection = $db->onGoingIp;
		$val = $collection->findOne();
		if( $val == null or $val == NULL || $val == "")
			echo "true";
		else
			echo "false";
	}
	else if($category == "selfServeInput")
	{
		$db = $client->config;
		$collection = $db->external;
		$db = $collection->findOne();
		$db = $db["SELF_SERVE_DATABASE"];
		$db = $client->$db;
	
		$data = $_POST["selfServeInput"];
	
		$collection = $db->onGoingIp;
		$val = $collection->findOne();
		foreach($data as $a_input)
		{
			$collection = $db->onGoingIp;
			$collection->insert($a_input);

			$collection = $db->ipInventory;
			$val = $collection->findOne(array("ip" => $a_input["ip"]));
			if($val == null or $val == NULL or $val == ""){ 
				$collection->insert($a_input);
			}
		}
		system("cd /TeamPirates/Watchdog/External && sudo python selfServeStart.py" , $output);
	}
	else if($level == "1" and $category == "uniqueCriticalVul")
	{
        $unique_critical_cve = array();       // [ [cve=><cve>,technology=><tech>,ver=><version>,ips=> [[ip=><ip>,domain=><domain>]..]]..]

        $collection = $db->technologies;
		$tech_list = $collection->find();
		foreach( $tech_list as $tech)
		{
			foreach( $tech as $key => $value)
			{
				if($key != "ip" and $key != "domain" and $key != "_id")
				{
					if( $value["false_positive"] != "0")
						continue;
					foreach( $value["cves"] as $CVE)
					{
						if( $CVE["cvss"] >= $scale_critical_vul_cve_external)
							find_unique_vul_external($unique_critical_cve , $tech , $key , $value , $CVE);
					}
				}
			}
		}
		$db = $client->cvedb;
		$collection = $db->cves;
		$size = sizeof($unique_critical_cve);
		for ($i=0; $i < $size; $i++) { 
			$summary = $collection->findOne(array("id" => $unique_critical_cve[$i]["cve"]));
			$summary = $summary["summary"];
			$unique_critical_cve[$i]["summary"] = $summary;
		}
		echo json_encode($unique_critical_cve);
	}

	else if($level == "1" and $category == "uniqueHighVul")
	{
        $unique_high_cve = array();       // [ [cve=><cve>,technology=><tech>,ver=><version>,ips=> [[ip=><ip>,domain=><domain>]..]]..]

        $collection = $db->technologies;
		$tech_list = $collection->find();
		foreach( $tech_list as $tech)
		{
			foreach( $tech as $key => $value)
			{
				if($key != "ip" and $key != "domain" and $key != "_id")
				{
					if( $value["false_positive"] != "0")
						continue;
					foreach( $value["cves"] as $CVE)
					{
						if( $CVE["cvss"] >= $scale_high_vul_cve_external and $CVE["cvss"] < $scale_critical_vul_cve_external)
							find_unique_vul_external($unique_high_cve , $tech , $key , $value , $CVE);
					}
				}
			}
		}
		$db = $client->cvedb;
		$collection = $db->cves;
		$size = sizeof($unique_high_cve);
		for ($i=0; $i < $size; $i++) { 
			$summary = $collection->findOne(array("id" => $unique_high_cve[$i]["cve"]));
			$summary = $summary["summary"];
			$unique_high_cve[$i]["summary"] = $summary;
		}
		echo json_encode($unique_high_cve);
	}

	else if( $level == "1" and $category == "uniqueServices")
	{
		$collection = $db->services;
        $ip_list = $collection->find();
        
        $unique_services = array();
        $size_unique_services = 0;
        foreach($ip_list as $x){
        	foreach ($x as $key => $value) {
        		if($key	!= "ip" and $key != "domain" and $key != "_id" and $key != "md5")
        		{
        			if( $value["false_positive"] != "0")
        				continue;
        			$i = 0;
        			for ($i=0; $i < $size_unique_services; $i++) { 
        				if($unique_services[$i]["name"] == $key)
        				{
        					$size = sizeof($unique_services[$i]["details"]);
        					$j = 0;
        					for ($j=0; $j < $size; $j++) { 
        						if($unique_services[$i]["details"][$j]["version"] == $value){
        							array_push($unique_services[$i]["details"][$j]["ips"], array("ip" => $x["ip"] , "domain" => $x["domain"]));
        							break;
        						}
        					}
        					if( $j == $size)
        					{
        						$temp = array( "version" => $value , "ips" => array(array("ip" => $x["ip"] , "domain" => $x["domain"])));
        						array_push($unique_services[$i]["details"], $temp);
        					}
        					break;
        				}
        			}
        			if($i == $size_unique_services)
        			{
        				$temp = array( "version" => $value , "ips" => array(array("ip" => $x["ip"] , "domain" => $x["domain"])));
        				array_push($unique_services, array("name" => $key , "details" => array($temp)));
        				$size_unique_services++;
        			}
        		}
        	}
        }
		echo json_encode($unique_services);        
	}

	else if( $level == "1" and $category == "frontEndTech")
	{
		$most_used_tech = array();

        $collection = $db->technologies;
		$tech_list = $collection->find();
		foreach( $tech_list as $tech)
		{
			foreach( $tech as $key => $value)
			{
				if($key != "ip" and $key != "domain" and $key != "_id")
				{
					if( $value["false_positive"] != "0")
						continue;
					$size = sizeof($most_used_tech);
					$i = 0;
					for ($i=0; $i < $size; $i++) 
					{ 
						if($most_used_tech[$i]["name"] == $key)
						{
							$s = sizeof($most_used_tech[$i]["details"]);
							for ($j=0; $j < $s; $j++) { 
								if($most_used_tech[$i]["details"][$j]["version"] == $value["version"])
								{
									$temp = array("ip" => $tech["ip"] , "domain" => $tech["domain"]);
									array_push($most_used_tech[$i]["details"][$j]["ips"], $temp );
									break;
								}
							}
							if($j == $s)
							{
								$highest_cvss_tech = 0;
								foreach( $value["cves"] as $a_cve)
								{
									if( $a_cve["cvss"] > $highest_cvss_tech)
										$highest_cvss_tech = $a_cve["cvss"];
								}
								$x = array();
								$temp = array("ip" => $tech["ip"] , "domain" => $tech["domain"]);
								array_push($x, $temp);
								$entry = array( "version" => $value["version"] , "ips" => $x , "cves" => $value["cves"] , "highest_cvss" => $highest_cvss_tech);
								array_push( $most_used_tech[$i]["details"] , $entry );
							}
							break;
						}
					}
					if($i == $size)
					{	
						$highest_cvss_tech = 0;
						foreach( $value["cves"] as $a_cve)
						{
							if( $a_cve["cvss"] > $highest_cvss_tech)
								$highest_cvss_tech = $a_cve["cvss"];
						}
						$x = array();
						$temp = array("ip" => $tech["ip"] , "domain" => $tech["domain"]);
						array_push($x, $temp);
						$entry = array("version" => $value["version"] , "ips" => $x , "cves" => $value["cves"], "highest_cvss" => $highest_cvss_tech);
						$y = array();
						array_push($y, $entry);
						$final_entry = array("name" => $key , "details" => $y);
						
						array_push($most_used_tech , $final_entry);
					}
				}
			}
		}
		echo json_encode($most_used_tech); 
	}

	else if($level == "1" and $category == "uniqueVul")
	{
        $unique_cve = array();       // [ [cve=><cve>,technology=><tech>,ver=><version>,ips=> [[ip=><ip>,domain=><domain>]..]]..]

        $collection = $db->technologies;
		$tech_list = $collection->find();
		foreach( $tech_list as $tech)
		{
			foreach( $tech as $key => $value)
			{
				if($key != "ip" and $key != "domain" and $key != "_id")
				{
					if( $value["false_positive"] != "0")
						continue;
					foreach( $value["cves"] as $CVE)
						find_unique_vul_external($unique_cve , $tech , $key , $value , $CVE);
				}
			}
		}
		$db = $client->cvedb;
		$collection = $db->cves;
		$size = sizeof($unique_cve);
		for ($i=0; $i < $size; $i++) { 
			$summary = $collection->findOne(array("id" => $unique_cve[$i]["cve"]));
			$summary = $summary["summary"];
			$unique_cve[$i]["summary"] = $summary;
		}
		echo json_encode($unique_cve);
	}

	else if( $level == "1" and  $category =="ipCount")				// not needed.
	{
		$collection = $db->services;
        $ip_list = $collection->find();

        $ip_scanned = array();

        foreach($ip_list as $ip)
        	array_push($ip_scanned, $ip["ip"]);
        
        echo json_encode($ip_scanned);
	}
	else if( $level == "1")
	{
		$collection = $db->services;
        
        $ip_count = 0;
        $unique_cve = array();

        $unique_services = array();
        $top3_services = array();

        $high_severity_issues = 0;
        $critical_severity_issues = 0;
        $most_used_tech = array();

        
        $services_list = $collection->find();
        
        $total_services = 0;
        
        foreach($services_list as $x){
        	$ip_count = $ip_count + 1;
        	foreach ($x as $key => $value) {
        		if($key	!= "ip" and $key != "domain" and $key != "_id" and $key != "md5")
        		{
        			if( $value["false_positive"] != "0")
        				continue;
        			$total_services++;
        			$i = 0;
        			$size = sizeof($unique_services);
        			for ($i=0; $i < $size; $i++) { 
        				if($unique_services[$i]["name"] == $key){
        					$unique_services[$i]["value"]++;
        					break;
        				}
        			}
        			if($i == $size)
        				array_push($unique_services, array("name" => $key , "value" => 1));
        		}
        	}
        }
		$top3_services = find_top3($unique_services);
		$other_services = array("name" => "others" , "value" => $total_services);
		
		for ($i=0; $i < sizeof($top3_services); $i++) { 
			$other_services["value"] -= $top3_services[$i]["value"];
		}

		array_push($top3_services, $other_services);
        
        $total_technologies = 0;
        $collection = $db->technologies;
		$tech_list = $collection->find();
		foreach( $tech_list as $tech)
		{
			foreach( $tech as $key => $value)
			{
				if($key != "ip" and $key != "domain" and $key != "_id")
				{
					if( $value["false_positive"] != "0")
						continue;
					$total_technologies++;
					$size = sizeof($most_used_tech);
					$i = 0;
					for ($i=0; $i < $size; $i++) { 
						if($most_used_tech[$i]["name"] == $key){
							$most_used_tech[$i]["value"]++;
							break;
						}
					}
					if($i == $size)
					{
						$temp = array("name" => $key , "value" => 1);
						array_push($most_used_tech , $temp);
					}

					foreach( $value["cves"] as $CVE){
						if( in_array($CVE["id"], $unique_cve) == false)
						{
							
							if( $CVE["cvss"] >= $scale_critical_vul_cve_external)
								$critical_severity_issues++;
							else if($CVE["cvss"] >= $scale_high_vul_cve_external)
								$high_severity_issues++;

							array_push($unique_cve, $CVE["id"]);
						}
					}
				}
			}
		}
		$top3_tech = array();
		$top3_tech = find_top3($most_used_tech);
		$other_tech = array("name" => "others" , "value" => $total_technologies);
		
		for ($i=0; $i < sizeof($top3_tech); $i++) { 
			$other_tech["value"] = $other_tech["value"] - $top3_tech[$i]["value"];
		}

		array_push($top3_tech, $other_tech);
		
		$uniqueHighSeverityExt = array();
		array_push($uniqueHighSeverityExt, array("name" => "critical" , "value" => $critical_severity_issues));
		array_push($uniqueHighSeverityExt, array("name" => "high" , "value" => $high_severity_issues));
		array_push($uniqueHighSeverityExt, array("name" => "others" , "value" => (sizeof($unique_cve) - $critical_severity_issues - $high_severity_issues)));
		$result = array("ipCount" => $ip_count , "uniqueCVE" => sizeof($unique_cve) , "topServices" => $top3_services , "uniqueHighSeverityExt" => $uniqueHighSeverityExt , "top3Tech" => $top3_tech , "totalTechnologies" => $total_technologies);
		echo json_encode($result);
	}

	else if($level == "2")
	{
		if( $category == "history")
		{
			$db = $client->config;
			$collection = $db->external;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

        $collection = $db->services;
        $ip_list = $collection->find();
		$ip_domain = array();
		$last_scanned = "0";
    	foreach( $ip_list as $ip )
    	{
    		$unique_services = 0;
    		if( $category == "history"){
    			$unique_services = sizeof($ip) -5;
    			$last_scanned = $ip["time"];
    		}
    		else
    			$unique_services = sizeof($ip) -4;

    		foreach ($ip as $key => $value) 
    		{
    			if($key != "ip" and $key != "domain" and $key != "md5" and $key != "_id" and $key !="time")
    			{
    				if( $value["false_positive"] != "0")
    					$unique_services--;
    			}
    		}
    		if($unique_services <0)
    			$unique_services = 0;
    		$unique_technologies = 0;


			$highest_cvss = 0;
		    $CVE_count = ["total" => 0 , "critical" => 0 , "high" => 0 , "medium" => 0 , "low" => 0];

			$collection = $db->technologies;
			$tech = $collection->findOne(array("ip" => $ip["ip"]));
			$unique_technologies = sizeof($tech) -3;
			foreach( $tech as $key => $value)
			{
				if($key != "ip" and $key != "domain" and $key != "_id" and $value["false_positive"] != "0"){
					$unique_technologies--;
					continue;
				}
				else if($key != "ip" and $key != "domain" and $key != "_id")
				{
					foreach( $value["cves"] as $CVE)
					{
						if( $CVE["cvss"] > $highest_cvss)
							$highest_cvss = $CVE["cvss"];
						
						$CVE_count["total"]++;
						if( floatval($CVE["cvss"]) >= $scale_critical_vul_cve_external)
							$CVE_count["critical"]++;
						else if( floatval($CVE["cvss"]) >= $scale_high_vul_cve_external)
							$CVE_count["high"]++;
						else if( floatval($CVE["cvss"]) >= $scale_medium_vul_cve_external)
							$CVE_count["medium"]++;
						else
							$CVE_count["low"]++;
					}
				}
			}
			if( $unique_technologies < 0)
				$unique_technologies = 0;
			
			if( $highest_cvss == 0)
				$highest_cvss = "";
			$collection = $db->vulnerabilities;
			$web_vul = $collection->findOne(array("ip" => $ip["ip"]));
			$web_vul_count = $web_vul["count"];
			if( $category == "history")
			{
				$new_entry = array("ip" => $ip["ip"] , "domain" => $ip["domain"] , "unique_services" => $unique_services , "unique_technologies" => $unique_technologies , "highest_cvss" => $highest_cvss , "cve_count" => $CVE_count , "time" => $last_scanned , "web_vul_count" => $web_vul_count);	
			}
			else
			{
				$new_entry = array("ip" => $ip["ip"] , "domain" => $ip["domain"] , "unique_services" => $unique_services , "unique_technologies" => $unique_technologies , "highest_cvss" => $highest_cvss , "cve_count" => $CVE_count, "web_vul_count" => $web_vul_count);
			}	
			array_push($ip_domain , $new_entry);
    	}
		echo $jsonformat = json_encode($ip_domain);
	}
	else if(  $level == "3" and ( $category == "bargraphdata" or $category == "bargraphdataHistory" ))
	{
		if( $category == "bargraphdataHistory")
		{
			$db = $client->config;
			$collection = $db->external;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

		$input_ip = correct_ip($input_ip);

		$collection = $db->services;
		$ip_list = $collection->findOne(array('ip' => $input_ip));
		$port_counting = 0;
		if( $category == "bargraphdataHistory")
			$port_counting = sizeof($ip_list) - 5;
		else	
        	$port_counting = sizeof($ip_list) - 4;
        $false_positive_services = 0;
        foreach ($ip_list as $key => $value) {
        	if($key != "_id" and $key != "ip" and $key != "domain" and $key != "md5" and $key != "time"){
        		if($value["false_positive"] != "0")
        			$false_positive_services++;	
        	}
        }
        $port_counting -= $false_positive_services;
        if($port_counting < 0)
        	$port_counting = 0;
        
    	$port_count = array($port_counting,$false_positive_services);;

    	$collection = $db->technologies;
        $ip_list = $collection->findOne(array('ip' => $input_ip));
        $false_positive_technologies = 0;
        foreach ($ip_list as $key => $value) {
        	if($key != "_id" and $key != "ip" and $key != "domain" and $key != "md5"){
        		if($value["false_positive"] != "0")
        			$false_positive_technologies++;	
        	}
        }
        $tech_counting = sizeof($ip_list) - 3 - $false_positive_technologies;
        if($tech_counting < 0)
        	$tech_counting = 0;
        $tech_count = array($tech_counting,$false_positive_technologies);


        $critical_severity_issues = 0;
        $high_severity_issues = 0;
        $medium_severity_issues = 0;
        $low_severity_issues = 0;
        $collection = $db->technologies;
        $tech = $collection->findOne(array('ip' => $input_ip));
	
		$false_critical = 0;
		$false_high = 0;
		$false_medium = 0;
		$false_low = 0;
		$falsify = "0";
		foreach( $tech as $key => $value)
		{
			if($key != "ip" and $key != "domain" and $key != "_id")
			{
				if( $value["false_positive"] != "0")
					$falsify = "1";
				else
					$falsify = "0";
				foreach( $value["cves"] as $CVE){
					
					if( $CVE["cvss"] >= $scale_critical_vul_cve_external){
						if( $falsify == "1")
							$false_critical++;
						else
							$critical_severity_issues++;
					}
					else if($CVE["cvss"] >= $scale_high_vul_cve_external){
						if( $falsify == "1")
							$false_high++;
						else
							$high_severity_issues++;
					}
					else if($CVE["cvss"] >= $scale_medium_vul_cve_external){
						if( $falsify == "1")
							$false_medium++;
						else
							$medium_severity_issues++;
					}
					else{
						if($falsify == "1")
							$false_low++;
						else
							$low_severity_issues++;
					}
				}
			}
		}
		
		$critical_cve_count = array($critical_severity_issues,$false_critical);
		$high_cve_count = array($high_severity_issues, $false_high);
		$medium_cve_count = array($medium_severity_issues, $false_medium);
		$low_cve_count = array($low_severity_issues, $false_low);	

		$result = array("port_count" => $port_count , "tech_count" => $tech_count , "critical_cve_count" => $critical_cve_count , "high_cve_count" => $high_cve_count , "medium_cve_count" => $medium_cve_count , "low_cve_count" => $low_cve_count);

		echo json_encode($result);

    }
	else if(  $level == "3" and ( $category == "services" or $category == "servicesHistory" ))
	{
		if( $category == "servicesHistory")
		{
			$db = $client->config;
			$collection = $db->external;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

		$input_ip = correct_ip($input_ip);

		$collection = $db->services;
		$ip_list = $collection->find(array('ip' => $input_ip));
        $ipList = array();
        foreach( $ip_list as $document){
            array_push($ipList ,  $document);
        }
        echo $jsonformat = json_encode($ipList);
	}
	else if(  $level == "3" and ( $category == "technologies" or $category == "technologiesHistory" ))
    {
    	if( $category == "technologiesHistory")
		{
			$db = $client->config;
			$collection = $db->external;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

		$input_ip = correct_ip($input_ip);

        $collection = $db->technologies;
        $ip_list = $collection->find(array('ip' => $input_ip));
        $ipList = array();
        foreach( $ip_list as $document){
        	
            foreach ($document as $key => $value) {
            	$highest_cvss = 0;
            	if($key !="ip" and $key != "domain" and $key != "md5" and $key != "_id")
            	{
            		foreach ($value["cves"] as $CVE) {
            			if($CVE["cvss"] > $highest_cvss)
            				$highest_cvss = $CVE["cvss"];
            		}
            		$document[$key]["highest_cvss"] = $highest_cvss;
            	}
            }
            array_push($ipList ,  $document);
        }
        echo $jsonformat = json_encode($ipList);
    }
	else if( $level == "3" and ( $category == "vulnerabilities" or $category == "vulnerabilitiesHistory") )
	{
		if( $category == "vulnerabilitiesHistory")
		{
			$db = $client->config;
			$collection = $db->external;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

		$input_ip = correct_ip($input_ip);

		$collection = $db->vulnerabilities;
        $ip_list = $collection->find(array('ip' => $input_ip));

		$ipList = array();
        foreach( $ip_list as $document){
            array_push($ipList ,  $document);
        }

        $ipList[0]["wapiti"] = str_replace($_SERVER['DOCUMENT_ROOT'],"",$ipList[0]["wapiti"])."/index.html";
        $ipList[0]["skipfish"] = str_replace($_SERVER['DOCUMENT_ROOT'],"",$ipList[0]["skipfish"])."/index.html";

        echo json_encode($ipList);
	}
}
else if($type == "internal")
{
	$db = $client->config;
	$collection = $db->internal;
	$db = $collection->findOne();
	$db = $db["DATABASE"];
	$db = $client->$db;
	
	$collection = $db->dependency_checker;
	if( $category == "showToken")
	{
		$db = $client->config;
		$collection = $db->internal;
		$tt = $collection->findOne();
		$previous = $tt["GIT_TOKEN"];
		$len = strlen($previous);
		$len--;
		while($previous[$len] == ' ')
			$len--;
		for ($i=0; $i < $len-3; $i++) { 
			$previous[$i] = 'x';
		}
		echo json_encode($previous);
	}
	else if( $category == "changeToken")
	{
		$token = $_POST["changeToken"];
		$db = $client->config;
		$collection = $db->internal;
		$tt = $collection->findOne();
		$previous = $tt["GIT_TOKEN"];

		$collection->update(array("GIT_TOKEN" => $previous) , array("$set" => array("GIT_TOKEN" => $token)));
	}
	else if( $category == "checkSelfServeInput")
	{
		$db = $client->config;
		$collection = $db->internal;
		$db = $collection->findOne();
		$db = $db["SELF_SERVE_DATABASE"]; 
		$db = $client->$db;
	
	//	$data = $_POST["checkSelfServeInput"];
	//	echo json_encode($data);

		$collection = $db->toScan;
		$val = $collection->findOne();
		if( $val == null or $val == NULL || $val == "")
			echo "true";
		else
			echo "false";
	}
	else if($category == "selfServeInput")
	{
		$db = $client->config;
		$collection = $db->internal;
		$db = $collection->findOne();
		$db = $db["SELF_SERVE_DATABASE"];
		$db = $client->$db;
	
		$data = $_POST["selfServeInput"];
	//	echo json_encode($data);

		$collection = $db->toScan;
		$val = $collection->findOne();
		foreach($data as $a_input){
			$collection = $db->toScan;
			$collection->insert($a_input);
		}
		system("cd /TeamPirates/Watchdog/Internal && sudo python self_serve_start.py");
		
	}
	else if($category == "firstTimeInput")
	{
		$organisation = $_POST["orgName"];
		$token = $_POST["token"];
		//echo $organisation." ".$token;
		$db = $client->config;
		$collection = $db->internal;
		$db = $collection->findOne();
		$db = $db["DATABASE"];
		$db = $client->$db;

		$collection = $db->toScan;
		$val = $collection->findOne();
		echo $organisation." ".$token;
		if($val == null or $val == NULL or $val == ""){
			echo "true";														// run script internalStart.py
			
			$db = $client->config;
			$collection = $db->internal;
			$database_name = $collection->findOne()["DATABASE"];
			echo $database_name;
			$collection->update(array('DATABASE' => $database_name), array('$set' => array('GIT_TOKEN' => $token)));
			$collection->update(array('DATABASE' => $database_name), array('$set' => array('ORGANISATION' => $organisation)));
	//		exec("cd /TeamPirates/Watchdog/Internal && sudo python /TeamPirates/Watchdog/Internal/internal_start.py");
		}
		else
			echo "false";
	}
	else if($category == "falsePositiveDep" or $category == "selfServeFalsePositiveDep")
	{
	//	echo "maaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		if( $category == "selfServeFalsePositiveDep")
		{
			$db = $client->config;
			$collection = $db->internal;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

		$dependency_names = $_POST["dependencies"];
		$date_data = $_POST["date"];
		echo $dependency_names[0];

		$collection = $db->dependency_checker;
		echo $date_data;

		foreach( $dependency_names as $a_dependency)
		{
	//		echo $a_dependency;
			$val = $collection->findOne(array("dependency" => $a_dependency));
			$flag = $val["false_positive"];
			if($flag == "0")
				$flag = $date_data;
			else
				$flag = "0";
			$collection->update(array('dependency'=>$a_dependency),array('$set' => array( 'false_positive' => $flag ) ), array('multiple' => true));
	//		echo $flag;
		}
	}
	else if($category == "falsePositiveSource" or $category == "selfServeFalsePositiveSource")
	{
		if( $category == "selfServeFalsePositiveSource")
		{
			$db = $client->config;
			$collection = $db->internal;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}
		$collection = $db->source_scanner;
		$false_positive_data = $_POST["sourceCode"];
		$date_data = $_POST["date"];
		$category = $false_positive_data["category"];
		$repo = $false_positive_data["repo"];
		$files = $false_positive_data["files"];

		$val = $collection->findOne(array("RepoName" => $repo));
		$val = $val["Categories"];
		$size = sizeof($val);
		$Low = $High = $Critical = $Warning = $Informational = 0;
		for ($i=0; $i < $size; $i++) 
		{ 
			if(strtolower($val[$i]["Name"]) == strtolower($category))
			{
				foreach( $false_positive_data["files"] as $a_file)
				{
					$size_a_category = sizeof($val[$i]["Files"]);
					for ($j=0; $j < $size_a_category; $j++) 
					{
						if( strtolower($val[$i]["Files"][$j]["file"]) == strtolower($a_file)){
							$flag = $val[$i]["Files"][$j]["false_positive"];
							if( $flag == "0")
								$flag = $date_data;
							else
								$flag = "0"; 
							$val[$i]["Files"][$j]["false_positive"] = $flag;
							if( $flag != "0")
							{
								if($val[$i]["Files"][$j]["level"] == "Critical")
									$Critical++;
								else if($val[$i]["Files"][$j]["level"] == "High")
									$High++;
								else if($val[$i]["Files"][$j]["level"] == "Warning")
									$Warning++;
								else if($val[$i]["Files"][$j]["level"] == "Low")
									$Low++;
								else if($val[$i]["Files"][$j]["level"] == "Informational")
									$Informational++;
							}
							else
							{
								if($val[$i]["Files"][$j]["level"] == "Critical")
									$Critical--;
								else if($val[$i]["Files"][$j]["level"] == "High")
									$High--;
								else if($val[$i]["Files"][$j]["level"] == "Warning")
									$Warning--;
								else if($val[$i]["Files"][$j]["level"] == "Low")
									$Low--;
								else if($val[$i]["Files"][$j]["level"] == "Informational")
									$Informational--;	
							}
						}
					}
				}
				$val[$i]["false_count"]["Critical"] += $Critical;

				$val[$i]["false_count"]["High"] += $High;

				$val[$i]["false_count"]["Warning"] += $Warning;

				$val[$i]["false_count"]["Low"] += $Low;

				$val[$i]["false_count"]["Informational"] += $Informational;
				break;
			}
		}
		echo "hahahahahahahaahahahahahaahahah";
		echo $val[$i]["false_count"]["Critical"]." ".$val[$i]["false_count"]["High"]." ".$val[$i]["false_count"]["Warning"]." ".$val[$i]["false_count"]["Low"]." ".$val[$i]["false_count"]["Informational"];
		$collection->update(array('RepoName' => $repo), array('$set' => array('Categories' => $val)));


	}
	else if( $level == "1" and $category == "uniqueHighVulRepo")
	{
		$unique_high_vul_repo = array();
		$unique_repos = array();

	//	$collection = $db->source_scanner;
	//	$repos_source = $collection->find();

		$collection = $db->repos;
		$repo_in_repos = $collection->find();
		foreach( $repo_in_repos as $a_repo)
		{
			$last_scanned = $a_repo["lastEventScanned"];

			$collection = $db->source_scanner;
			$repo_source = $collection->findOne(array("RepoName" => $a_repo["name"]));			
			
			$highest_cvss = find_highest_cvss_internal($repo_source["RepoName"]);
	//		array_push($unique_repos, $repo_source["RepoName"]);
			$total_critical = $repo_source["TotalCount"]["Critical"];
			$false_count_critical = 0;
			foreach( $repo_source["Categories"] as $cat)
				$false_count_critical += $cat["false_count"]["Critical"];
			if( ($total_critical - $false_count_critical <= 0) and $highest_cvss < $scale_high_vul_repo)
				continue;
			

			$temp = array("repo_name" => $repo_source["RepoName"] , "highest_cvss" => $highest_cvss , "critical_count" => $total_critical - $false_count_critical , "last_scanned" => $last_scanned);
				array_push($unique_high_vul_repo, $temp);
		}
		echo json_encode($unique_high_vul_repo);
	}
	else if( $level == "1" and $category == "uniqueHighVulSource")
	{
		$collection = $db->source_scanner;
		$repos_source = $collection->find();

		$unique_high_vul_source = array();

		$critical_high = "High";
		perform_unique_source( $unique_high_vul_source , $repos_source , $critical_high);
		echo json_encode($unique_high_vul_source);
	}
	else if( $level == "1" and $category == "uniqueCriticalVulSource")
	{
		$collection = $db->source_scanner;
		$repos_source = $collection->find();

		$unique_critical_vul_source = array();

		$critical_high = "Critical";
		perform_unique_source( $unique_critical_vul_source , $repos_source , $critical_high);

		echo json_encode($unique_critical_vul_source);
	}
	else if( $level == "1" and $category == "uniqueVulSource")
	{
		$collection = $db->source_scanner;
		$repos_source = $collection->find();

		$unique_vul_source = array();

		foreach ($repos_source as $repo_source)
		{
			$name = $repo_source["Categories"];
			foreach ($name as $cat) 
			{
				$size = sizeof($unique_vul_source);
				$i = 0;
				for ($i=0; $i < $size; $i++ ) 
				{ 
					if($unique_vul_source[$i]["name"] == $cat["Name"])
					{
						$size_unique_vul_source = sizeof($unique_vul_source[$i]["repos"]);
						$kk = 0;
						for ($kk=0; $kk < $size_unique_vul_source; $kk++) { 
							if($unique_vul_source[$i]["repos"][$kk]["name"] == $repo_source["RepoName"])
								break;
						}
						if($kk == $size_unique_vul_source)
							array_push( $unique_vul_source[$i]["repos"] , array("name" => $repo_source["RepoName"]));
						break;
					}
				}
				if($i == $size)
				{
					$temp = array("name" => $repo_source["RepoName"]);
					$document = array("name" => $cat["Name"],"repos" => array($temp));
					array_push($unique_vul_source, $document);             
					// [[name => <category_name> , repos => [<repo1>,<repo2>...]]...]	
				
				}
			}
		}
		echo json_encode($unique_vul_source);
	}
	else if( $level == "1" and $category == "uniqueCVE")
	{
		$collection = $db->dependency_checker;
		$unique_cve = array();                            
		// [[cve=><cve>,cvss=><cvss_score>,repos=>[ [name:<repo_name>, dependencies:[<dep1>,<dep2>...]]]]
		
		$dependencies = $collection -> find();

		foreach( $dependencies as $dep)
		{
			if( $dep["false_positive"] != "0")
				continue;
			foreach( $dep["vulnerabilities"] as $a_vul)
			{
				$name = $a_vul["name"];
				perform_unique_cve( $unique_cve , $dep , $a_vul , $name);
			}
		}
		$db = $client->cvedb;
		$collection = $db->cves;
		$size = sizeof($unique_cve);
		for ($i=0; $i < $size; $i++) { 
			$summary = $collection->findOne(array("id" => $unique_cve[$i]["cve"]));
			$summary = $summary["summary"];
			$unique_cve[$i]["summary"] = $summary;
		}
		echo json_encode($unique_cve);
	}
	else if($level == "1" and $category == "uniqueCriticalVulCVE")
	{
		$collection = $db->dependency_checker;

		$unique_critical_vul_cve = array();     
		// [[cve=><cve>,cvss=><cvss_score>,repos=>[<repo1>,<repo2>...]]..]
		
		$dependencies = $collection -> find();

		foreach( $dependencies as $dep)
		{
			if( $dep["false_positive"] != "0")
				continue;
			foreach( $dep["vulnerabilities"] as $a_vul)
			{
				$name = $a_vul["name"];
				if( $a_vul["cvss_score"] >= $scale_critical_vul_cve_internal)
					perform_unique_cve( $unique_critical_vul_cve , $dep , $a_vul , $name);
			}
		}
		$db = $client->cvedb;
		$collection = $db->cves;
		$size = sizeof($unique_critical_vul_cve);
		for ($i=0; $i < $size; $i++) { 
			$summary = $collection->findOne(array("id" => $unique_critical_vul_cve[$i]["cve"]));
			$summary = $summary["summary"];
			$unique_critical_vul_cve[$i]["summary"] = $summary;
		}
		echo json_encode($unique_critical_vul_cve);
	}
	else if($level == "1" and $category == "uniqueHighVulCVE")
	{
		$collection = $db->dependency_checker;

		$unique_high_vul_cve = array();     
		// [[cve=><cve>,cvss=><cvss_score>,repos=>[<repo1>,<repo2>...]]..]
		
		$dependencies = $collection -> find();

		foreach( $dependencies as $dep)
		{
			if( $dep["false_positive"] != "0")
				continue;
			foreach( $dep["vulnerabilities"] as $a_vul)
			{
				$name = $a_vul["name"];
				if( floatval($a_vul["cvss_score"]) >= $scale_high_vul_cve_internal and floatval($a_vul["cvss_score"]) < $scale_critical_vul_cve_internal)
					perform_unique_cve( $unique_high_vul_cve , $dep , $a_vul , $name);
			}
		}
		$db = $client->cvedb;
		$collection = $db->cves;
		$size = sizeof($unique_high_vul_cve);
		for ($i=0; $i < $size; $i++) { 
			$summary = $collection->findOne(array("id" => $unique_high_vul_cve[$i]["cve"]));
			$summary = $summary["summary"];
			$unique_high_vul_cve[$i]["summary"] = $summary;
		}
		echo json_encode($unique_high_vul_cve);
	}
	else if($level == "1" and $category == "uniqueDependencies")
	{
		$collection = $db->dependency_checker_non_vul;
		$dependency = $collection->find();
		$result = array();

		foreach ($dependency as $a_dep) {
			array_push($result, $a_dep);
		}
		echo json_encode($result);
		//echo "haha";
	}
	else if($level == "1" and $category != "lastScannedRepos")
	{	
		$unique_cve = array();
		$unique_high_vul_cve = array();
		$unique_critical_vul_cve = array();
		$unique_high_vul_repo = array();
		$unique_repos = array();

		$repos_scanned = 0;
		$collection = $db->repos;
		$repo_in_repos = $collection->find();
		$ccc = 0;
		$repos_last_scanned = array();
		foreach( $repo_in_repos as $a_repo)
		{
			if( $a_repo["lastEventScanned"] != 0)
			{
				$repos_scanned++;
				$today = date("Y-m-d");
				$date = substr($today, -2);
				$date = (int)$date;

				$scan_date = substr( $a_repo["lastEventScanned"] , -2);
				$scan_date = (int)$scan_date;

				if( $ccc < 10)
				{
					$ccc++;
					$temp = array( "name" => $a_repo["name"] , "last_scanned" => $a_repo["lastEventScanned"]);
					array_push($repos_last_scanned, $temp);
				}
			}
		}
		$collection = $db->dependency_checker_non_vul;
		$critical_dependencies = 0;
		$high_dependencies = 0;
		$medium_dependencies = 0;
		$low_dependencies = 0;


		$dependencies_all = $collection -> find();
		foreach ($dependencies_all as $a_dependency) {
			if( $a_dependency["highest_cvss"] >= $scale_critical_vul_cve_internal)
				$critical_dependencies++;
			else if( $a_dependency["highest_cvss"] >= $scale_high_vul_cve_internal)
				$high_dependencies++;
			else if( $a_dependency["highest_cvss"] >= $scale_medium_vul_cve_internal)
				$medium_dependencies++;
			else if( $a_dependency["highest_cvss"] != 0)
				$low_dependencies++;
		}

		$counting = $collection->count();
		$unique_vul_dependencies = array("total" => $counting , "critical" => $critical_dependencies , "high" => $high_dependencies , "medium" => $medium_dependencies , "low" => $low_dependencies);
	
		$collection = $db->dependency_checker;

		$dependencies = $collection -> find();

		$count_critical_vul_cve_internal = 0;
		$count_high_vul_cve_internal = 0;
		$count_medium_vul_cve_internal = 0;
		$count_low_vul_cve_internal = 0;
		foreach( $dependencies as $dep)
		{
			if( $dep["false_positive"] !="0"){
				continue;
			}
			$name = $dep["repository_name"];
			if(in_array($name, $unique_repos) == true){
				continue;
			}
			array_push($unique_repos, $name);
			$a_repo = $collection -> find(array("repository_name" => $name));
			$flag = 0;
			$highest_cvss_count = 0;
			foreach ($a_repo as $a_dep) {
				if( $a_dep["false_positive"] !="0"){
					continue;
				}
				if($flag == 0 and $a_dep["highest_cvss"] >= $scale_high_vul_repo)
				{
					$flag = 1;
					array_push($unique_high_vul_repo , $name);	
				}
				if( $a_dep["highest_cvss"] > $highest_cvss_count )
					$highest_cvss_count = $a_dep["highest_cvss"];
				foreach( $a_dep["vulnerabilities"] as $a_vul)
				{
					if( in_array($a_vul["name"], $unique_cve) == false){
						array_push($unique_cve, $a_vul["name"]);
						if( floatval($a_vul["cvss_score"]) >= $scale_critical_vul_cve_internal)
							array_push($unique_critical_vul_cve, $a_vul["name"]);
						else if( floatval($a_vul["cvss_score"]) >= $scale_high_vul_cve_internal)
							array_push($unique_high_vul_cve, $a_vul["name"]);
					}
				}
			}
			if( $highest_cvss_count >= $scale_critical_vul_cve_internal)
				$count_critical_vul_cve_internal++;
			else if( $highest_cvss_count >= $scale_high_vul_cve_internal)
				$count_high_vul_cve_internal++;
			else if( $highest_cvss_count >= $scale_medium_vul_cve_internal)
				$count_medium_vul_cve_internal++;
			else
				$count_low_vul_cve_internal++;
		}

		$collection = $db->source_scanner;
		$repos_source = $collection->find();

		$unique_vul_source = array();
		$unique_critical_vul_source = 0;
		$unique_high_vul_source = 0;
		$others_vul_source = 0;

		$count_critical_source_internal = 0;
		$count_high_source_internal = 0;
		$count_warning_source_internal = 0;
		$count_low_source_internal = 0;

		foreach ($repos_source as $repo_source) {
			
			if( intval($repo_source["TotalCount"]["Critical"]) != 0)
				$count_critical_source_internal++;
			else if( intval($repo_source["TotalCount"]["High"]) != 0)
				$count_high_source_internal++;
			else if( intval($repo_source["TotalCount"]["Warning"]) != 0)
				$count_warning_source_internal++;
			else if( intval($repo_source["TotalCount"]["Low"]) != 0)
				$count_low_source_internal++;

			$name = $repo_source["Categories"];
			$unique_critical_vul_source += intval($repo_source["TotalCount"]["Critical"]);
			$this_unique_critical_vul_source = intval($repo_source["TotalCount"]["Critical"]);
			$unique_high_vul_source += intval($repo_source["TotalCount"]["High"]);
			$others_vul_source += intval($repo_source["TotalCount"]["Informational"]) + intval($repo_source["TotalCount"]["Low"]) + intval($repo_source["TotalCount"]["Warning"]);
			foreach ($name as $cat) {
				
				if( in_array($cat["Name"], $unique_vul_source) == false){
					array_push($unique_vul_source, $cat["Name"]);             // add severity here.
				}	
				$unique_critical_vul_source -= $cat["false_positive"]["Critical"];
				$unique_high_vul_source -= $cat["false_positive"]["High"];
				$others_vul_source -= ($cat["false_positive"]["Warning"] + $cat["false_positive"]["Low"] + $cat["false_positive"]["Informational"]);

				$this_unique_critical_vul_source -= $cat["false_positive"]["Critical"];
			}
			if( $this_unique_critical_vul_source > 0 and ( in_array($repo_source["RepoName"], $unique_high_vul_repo) == false))
				array_push($unique_high_vul_repo, $repo_source["RepoName"]);
		}

		$uniqueHighVulDepInt = array();
		array_push($uniqueHighVulDepInt, array("name" => "critical" , "value" => sizeof($unique_critical_vul_cve)));
		array_push($uniqueHighVulDepInt, array("name" => "high" , "value" => sizeof($unique_high_vul_cve)));
		array_push($uniqueHighVulDepInt, array("name" => "others" , "value" => sizeof($unique_cve) - sizeof($unique_critical_vul_cve) - sizeof($unique_high_vul_cve)));

		$uniqueHighVulSourceInt = array();
		array_push($uniqueHighVulSourceInt, array("name" => "critical" , "value" => $unique_critical_vul_source));
		array_push($uniqueHighVulSourceInt, array("name" => "high" , "value" => $unique_high_vul_source));
		array_push($uniqueHighVulSourceInt, array("name" => "others" , "value" => $others_vul_source));
		
		
		$collection = $db->repos;
		$java = 0.0;
		$javascript = 0.0;
		$python = 0.0;
		$ruby = 0.0;
		$total = 0.0;
		$hundred = 100.0;
		foreach( $unique_high_vul_repo as $repo)
		{
			$total += floatval($hundred);
			$repo_metadata = $collection->findOne(array("name" => $repo));
			foreach( $repo_metadata["language"] as $language => $percentage)
			{
				if( strtolower($language) == "java")
					$java += $percentage;
				else if( strtolower($language) == "javascript")
					$javascript += $percentage;
				if( strtolower($language) == "python")
					$python += $percentage;
				if( strtolower($language) == "ruby")
					$ruby += $percentage;
			}
		}
		$others = $total - $java- $javascript -$python -$ruby;
		$others = round( ($others/$total)*100.0 , 2);
		$java = round(($java/$total)*100.0 , 2);
		$javascript = round(($javascript/$total)*100.0 , 2);
		$python = round(($python/$total)*100.0 , 2);
		$ruby = round(($ruby/$total)*100.0 , 2);

		$cvss_wise_repos = array("critical" => $count_critical_vul_cve_internal , "high" => $count_high_vul_cve_internal , "medium" => $count_medium_vul_cve_internal , "low" => $count_low_vul_cve_internal);

		$source_wise_repos = array("critical" => $count_critical_source_internal , "high" => $count_high_source_internal , "medium" => $count_warning_source_internal , "low" => $count_low_source_internal);

		$languages = array(array("name" => "Java" , "value" => $java) , array("name" => "JavaScript" , "value" => $javascript) , array("name" => "Python" , "value" => $python) , array("name" => "Ruby" , "value" => $ruby) , array("name" => "others" , "value" => $others));
		$result = array("uniqueCVE" => sizeof($unique_cve) , "uniqueHighVulDepInt" => $uniqueHighVulDepInt , "uniqueHighVulSourceInt" => $uniqueHighVulSourceInt , "uniqueHighVulRepo" => sizeof($unique_high_vul_repo) , "uniqueVulSource" => sizeof($unique_vul_source) , "languages" => $languages , "tempUniqueHighVulRepo" => $unique_high_vul_repo , "repos_scanned" => $repos_scanned , "repos_last_scanned" => $repos_last_scanned , "cvssWiseRepos" => $cvss_wise_repos , "sourceWiseRepos" => $source_wise_repos , "unique_vul_dependencies" => $unique_vul_dependencies);

		echo json_encode($result);
	}
	else if($level == "2" or ( $level == "1" and $category == "lastScannedRepos") or ( $level == "2" and $category == "history"))
	{
		if( $category == "history")
		{
			$db = $client->config;
			$collection = $db->internal;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}

		$flag = array();
		$repoList = array();


		$collection = $db->repos;
		$repo_in_repos = $collection->find();
		
		foreach( $repo_in_repos as $a_repo_repos)
		{
			$flag_date = 0;
		//	echo $a_repo_repos["name"]." ".$a_repo_repos["lastEventScanned"]." ";
			if( $a_repo_repos["lastEventScanned"] != 0)
			{
				if( $level == "1" and $category == "lastScannedRepos" )
				{
					$flag_date = 1;
					$today = date("Y-m-d");
					$date = substr($today, -2);
					$date = (int)$date;

					$d = substr($a_repo_repos["lastEventScanned"] , -2);
					$d = (int)$d;

					if( $d == $date){
						$flag_date = 2;
					}
				}
				if( $flag_date == 0 or $flag_date == 2)
				{	
					$CVE_count = array("total" => 0,"critical" => 0, "high" => 0, "medium" => 0, "low" => 0);
					$highest_cvss = 0;
					$yasca_count = 0;
					$name = $a_repo_repos["name"];
					$last_scanned = $a_repo_repos["lastEventScanned"];

					$collection = $db->dependency_checker;
					$a_repo = $collection -> find(array("repository_name" => $name));
					foreach( $a_repo as $dep )
					{
						if($dep["false_positive"] != "0")
							continue;
						if( $highest_cvss < floatval($dep["highest_cvss"]))
							$highest_cvss = floatval($dep["highest_cvss"]);
						
						$CVE_count["total"]+= $dep["CVE_count"];
						$CVE_count["critical"]+= $dep["CVE_critical"];
						$CVE_count["high"]+= $dep["CVE_high"];
						$CVE_count["medium"]+= $dep["CVE_medium"];
						$CVE_count["low"]+= $dep["CVE_low"];
					}

					$collection = $db->source_scanner;
		    		$repo_details = $collection->findOne(array('RepoName' => $name));
		    		$source_categories = $repo_details["Categories"];
		    		$i = 0;
		    		$size_source_categories = sizeof($source_categories);
		   			for( $i = 0 ; $i < $size_source_categories ; $i++){
		            	$yasca_count = $yasca_count + ($source_categories[$i]["Count"]["Critical"] + $source_categories[$i]["Count"]["High"] + $source_categories[$i]["Count"]["Warning"] + $source_categories[$i]["Count"]["Low"] + $source_categories[$i]["Count"]["Informational"]);
		            	$yasca_count -= ( $source_categories[$i]["false_count"]["Critical"] + $source_categories[$i]["false_count"]["High"] + $source_categories[$i]["false_count"]["Informational"] + $source_categories[$i]["false_count"]["Low"] + $source_categories[$i]["Warning"]);
		   			}

		    		$collection = $db->dependency_checker;

					$new_entry = array("name" => $name, "CVE_count" => $CVE_count , "yasca_count" => $yasca_count , "highest_cvss" => $highest_cvss , "last_scanned" => $last_scanned);
					array_push($repoList, $new_entry);
				}
			}	
		}
		echo $jsonformat=json_encode($repoList);

	}
	else if($level == "3" and ( $category == "dependency" or $category == "dependencyHistory"))
	{
		if( $category == "dependencyHistory")
		{
			$db = $client->config;
			$collection = $db->internal;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		}
		$collection = $db->dependency_checker;

		$cursor = $collection->find(array('repository_name' => $repo));
		$repoDependencies = array();
		foreach( $cursor as $document){
			array_push($repoDependencies ,  $document);
        }

		echo $jsonformat = json_encode($repoDependencies);
	}
	else if($level == "3" and ( $category == "source" or $category == "sourceHistory") )
	{
		if ( $category == "sourceHistory" )
		{
			$db = $client->config;
			$collection = $db->internal;
			$db = $collection->findOne();
			$db = $db["SELF_SERVE_DATABASE"];
			$db = $client->$db;
		} 
		$collection = $db->source_scanner;
		$repo_details = $collection->findOne(array('RepoName' => $repo));
		$source_details = array();
		foreach ($repo_details as $key => $value) {
			if( $key != "Categories")
				$source_details[$key] = $value;
		}
		$flagging = 0;
		foreach( $repo_details["Categories"] as $document)
		{
			if($flagging == 0)
			{
				$tt = array($document);
				$source_details["Categories"] = $tt;
				$flagging = 1;
			}
			else{
				$size_cats = sizeof($source_details["Categories"]);
				for( $i = 0; $i < $size_cats ; $i++)
				{
					if($source_details["Categories"][$i]["Name"] == $document["Name"])
					{
						foreach ($document["Files"] as $a_file) {
							array_push($source_details["Categories"][$i]["Files"], $a_file);
						}
						$source_details["Categories"][$i]["Count"]["Critical"] += $document["Count"]["Critical"];
						$source_details["Categories"][$i]["Count"]["High"] += $document["Count"]["High"];
						$source_details["Categories"][$i]["Count"]["Warning"] += $document["Count"]["Warning"];
						$source_details["Categories"][$i]["Count"]["Low"] += $document["Count"]["Low"];
						$source_details["Categories"][$i]["Count"]["Informational"] += $document["Count"]["Informational"];

						$source_details["Categories"][$i]["false_count"]["Critical"] += $document["false_count"]["Critical"];
						$source_details["Categories"][$i]["false_count"]["High"] += $document["false_count"]["High"];
						$source_details["Categories"][$i]["false_count"]["Warning"] += $document["false_count"]["Warning"];
						$source_details["Categories"][$i]["false_count"]["Low"] += $document["false_count"]["Low"];
						$source_details["Categories"][$i]["false_count"]["Informational"] += $document["false_count"]["Informational"];

						break;
					}
				}
				if( $i == $size_cats)
					array_push($source_details["Categories"], $document);	
			}
		}
	
		$collection = $db->repos;
        $repo_metadata = $collection->findOne(array("name" => $repo));

        array_push($source_details, array("contributors" => $repo_metadata["contributors"]));
        array_push($source_details, array("owner" => $repo_metadata["owner"]));
        array_push($source_details, array("language" => $repo_metadata["language"]));
        array_push($source_details, array("private" => $repo_metadata["private"]));
		echo $jsonformat = json_encode($source_details);
	}
}
?>
