var uniqueVul_data = {};
var sortable = false;

$(document).ready(function(){
	var i=0;
	var url = "/server.php?type=external&level=1&category=uniqueHighVul";
	$.getJSON(url,function(data1){
		uniqueVul_data = data1;
		$('#table').bootstrapTable({
		    data:data1,
		    columns: [{
		        field: 'cve',
		        title: 'CVE Number',
		        valign: 'middle',
		        sortable: sortable,
		        formatter: function ( data, type, row ) 
	        		{
	                    return '<a href="http://web.nvd.nist.gov/view/vuln/detail?vulnId='+data+'">'+ data+'</a>';
	                }
		    }, {
		        field: 'summary',
		        title: 'Description',
		        valign: 'middle'
		    }, {
		        field: 'ips',
		        title: 'IPS',
		        align: 'center',
		        valign: 'middle',
		        sortable: sortable,
		        formatter: function ( data, type, row ) 
	        		{
	                    i=i+1;					
	        			if (data.length == 0){
	        				return data.length;
	        			}
	    				return '<a href="#" onclick="show_cves('+i+')" id="myBtn" class="btn btn-primary btn-sm" data-toggle="modal" data-target="#myModal" >'+data.length+"</a>";
	                }
		    }, {
		        field: 'technology',
		        title: 'Technology',
		        align: 'center',
		        valign: 'middle',
		        sortable: sortable
		    }, {
		        field: 'version',
		        title: 'Version',
		        align: 'center',
		        valign: 'middle',
		        sortable: sortable
		    }, {
		        field: 'cvss',
		        title: 'CVSS',
		        align: 'center',
		        valign: 'middle',
		        sortable: sortable,
		        formatter: function ( data, type, row ) 
		        {
		        	var class_name = "";

		        	if(data > 0)
		        		class_name = "btn-info";

		        	if(data > 3)
		        		class_name = "btn-primary";

		        	if(data > 5)
		        		class_name = "btn-warning";

		        	if(data > 7)
		        		class_name = "btn-danger";


		        	return '<button type="button" class="btn '+class_name+'">'+data+'</button>';
		        }
		    }]
		});
	});
});

function download_cves(){
	for(k in uniqueVul_data){
		var ips = uniqueVul_data[k].ips;
		uniqueVul_data[k]['ips'] = "";
		for(i in ips){
			uniqueVul_data[k]['ips'] = uniqueVul_data[k]['ips']+ips[i]['ip']+" | ";
		}
		// console.log(uniqueVul_data);
	}
	JSONToCSVConvertor(uniqueVul_data, "Unique High Vulnerabilities", true);
}

function show_cves(i){
	// console.log(tech_data[i-1].cves);
	$("#unique_table").bootstrapTable({
		data:uniqueVul_data[i-1].ips,
		columns: [{
			field: 'ip',
			title: 'IP',
			valign: 'middle',
			align: "center",
			sortable: sortable,
			formatter: function ( data, type, row ) 
        		{
    				return '<a href="/External/ip_analysis.php?ip='+data+'">'+data+"</a>";
                }
		},{
			field: 'domain',
			title: 'Domain',
			valign: 'middle',
			align: "center",
			sortable: sortable
		}]
	});

	$("#unique_table").bootstrapTable("load",uniqueVul_data[i-1].ips);
	$('#download_ips').click(function(){
        JSONToCSVConvertor(uniqueVul_data[i-1].ips, "Ips with Unique High Vulnerabilities", true);
    });
}
