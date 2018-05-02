var sortable = false;

$(document).ready(function(){
	$('#table').bootstrapTable({
	    url: "/server.php?type=external&level=2",
	    columns: [{
	        field: 'ip',
	        title: 'IP',
	        valign: 'middle',
	        sortable: sortable,
	        formatter: function ( data, type, row ) 
        		{
                    return '<a href="/External/ip_analysis.php?ip='+data+'">'+ data+'</a>';
                }
	    }, {
	        field: 'domain',
	        title: 'Domain Name',
	        valign: 'middle',
	        sortable: sortable
	    }, {
	        field: 'unique_services',
	        title: 'Unique Services',
	        align: 'center',
	        valign: 'middle',
	        sortable: sortable
	    }, {
	        field: 'unique_technologies',
	        title: 'Unique Technologies',
	        align: 'center',
	        valign: 'middle',
	        sortable: sortable
	    }, {
	        field: 'cve_count',
	        title: 'CVEs',
	        align: 'center',
	        valign: 'middle',
	        sortable: sortable,
	        formatter: function ( data, type, row ) 
        		{
        			var ele = '';
    				ele = ele+'<button type="button" class="btn btn-danger">'+data['critical']+'</button> ';
    				ele = ele+'<button type="button" class="btn btn-warning">'+data['high']+'</button> ';
    				ele = ele+'<button type="button" class="btn btn-primary">'+data['medium']+'</button> ';
    				ele = ele+'<button type="button" class="btn btn-info">'+data['low']+'</button>';
                    return ele;
                }
	    }, {
	        field: 'highest_cvss',
	        title: 'Highest CVSS',
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
	    }, {
	        field: 'web_vul_count',
	        title: 'Web Vuln Count',
	        align: 'center',
	        valign: 'middle',
	        sortable: sortable
	    } ]
	});
});

function download_ext(){
	var url = "/server.php?type=external&level=2";
	download_json(url,"External Assets");
}