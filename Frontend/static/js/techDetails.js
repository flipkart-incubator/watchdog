var uniqueVul_data = {};
var tech_data = [];
var sortable = false;

$(document).ready(function(){
	var i=0;
	var j=0;
	var url = "/server.php?type=external&level=1&category=frontEndTech";
	$.getJSON(url,function(data1){
		uniqueVul_data = data1;
		// console.log(uniqueVul_data);
		uniqueVul_data.forEach(function(ele){
			ele['details'].forEach(function(ele2){
				// console.log(ele2);
				ele2['name'] = ele['name'];
				tech_data.push(ele2);
			});
		});
		// console.log(data);
		$('#table').bootstrapTable({
		    data:tech_data,
		    columns: [{
		        field: 'name',
		        title: 'Name',
		        valign: 'middle',
		        sortable: sortable
		    }, {
		        field: 'version',
		        title: 'Version',
		        valign: 'middle',
		        sortable: sortable
		    }, {
		        field: 'ips',
		        title: 'Count',
		        align: 'center',
		        valign: 'middle',
		        sortable: sortable,
		        formatter: function ( data, type, row ) 
	        		{
	        			// console.log(data);
	                    i=i+1;
	        			if (data.length == 0){
	        				return data.length;
	        			}
	    				return '<a href="#" onclick="show_ips('+i+')" id="myBtn" class="btn btn-primary btn-sm" data-toggle="modal" data-target="#myModal" >'+data.length+"</a>";
	                }
		    }, {
		        field: 'cves',
		        title: 'CVEs',
		        align: 'center',
		        valign: 'middle',
		        sortable: sortable,
		        formatter: function ( data, type, row ) 
	        		{
	        			// console.log(data);
	                    j=j+1;
	        			if (data == null || data.length == 0){
	        				return data.length;
	        			}
	        			return '<a href="#" onclick="show_cves('+j+')" id="myBtn" class="btn btn-primary btn-sm" data-toggle="modal" data-target="#myModal" >'+data.length+"</a>";
	        		}
		    }, {
		        field: 'highest_cvss',
		        title: 'highest_cvss',
		        align: 'center',
		        valign: 'middle',
		        sortable: sortable
		    }]
		});
	});
});

function download_cves(){
	for(k in tech_data){
		var ips = tech_data[k].ips;
		tech_data[k]['ips'] = "";
		for(i in ips){
			tech_data[k]['ips'] = tech_data[k]['ips']+ips[i]['ip']+" | ";
		}
		// console.log(uniqueVul_data);
	}
	JSONToCSVConvertor(tech_data, "Unique Critical Vulnerabilities", true);
}

function show_ips(i){
	// console.log(tech_data[i-1].cves);
	$("#myModalLabel").text("IPs");
	$("#cves_table").hide();
	$('#download_cves').hide();

	$("#ips_table").bootstrapTable({
		data:tech_data[i-1].ips,
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

	$("#ips_table").bootstrapTable("load",tech_data[i-1].ips);
	$("#ips_table").show();

	$('#download_ips').click(function(){
        JSONToCSVConvertor(tech_data[i-1].ips, "Ips with Unique Critical Vulnerabilities", true);
    });
    $('#download_ips').show();
}

function show_cves(i){
	// console.log(tech_data[i-1].cves);
	$("#myModalLabel").text("CVEs");
	$("#ips_table").hide()
	$('#download_ips').hide();

	$("#cves_table").bootstrapTable({
		data:tech_data[i-1].cves,
		columns: [{
			field: 'id',
			title: 'CVE',
			valign: 'middle',
			align: "center",
			sortable: sortable,
			formatter: function ( data, type, row ) 
    		{
                return '<a href="http://web.nvd.nist.gov/view/vuln/detail?vulnId='+data+'">'+ data+'</a>';
            }
		},{
			field: 'cvss',
			title: 'CVSS',
			valign: 'middle',
			align: "center",
			sortable: sortable
		}]
	});

	$("#cves_table").bootstrapTable("load",tech_data[i-1].cves);
	$("#cves_table").show()

	$('#download_cves').click(function(){
        JSONToCSVConvertor(tech_data[i-1].cves, "CVEs with CVSS", true);
    });
    $('#download_cves').show();
}
