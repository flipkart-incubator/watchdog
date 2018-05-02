var services_data = {};
var tech_data = {};
var web_data = {};
var sortable = false;

$(document).ready(function(){
    var queryString = window.location.search;
    var ip = queryString.substring(1);
    fill_bar_chart(ip);
    get_services(ip);
    get_technologies(ip);
    get_web_vulns(ip);

    $("#myBtn").click(function(){
         $('#myModal').modal('show');
    });
});

window.service_fp = {
    'click .like': function (e, value, row, index) {
    	var url = "/server.php?type=external&category=falsePositivePort";
    	var data = {
    		"services[]": row.port,
    		ip: row.ip,
    		date: Date()
    	};

    	$.post(url, data, function(data1,success){
    		// console.log(data.ip);
    		fill_bar_chart("ip="+data.ip);
    	});
        // alert('You click like action, row: ' + JSON.stringify(row));
    }
};

window.tech_fp = {
    'click .like': function (e, value, row, index) {
    	console.log(row);
    	var url = "/server.php?type=external&category=falsePositiveTech";
    	var data = {
    		"technologies[]": row.tech,
    		ip: row.ip,
    		date: Date()
    	};

    	$.post(url, data, function(data1,success){
    		fill_bar_chart("ip="+data.ip);
    	});
        // alert('You click like action, row: ' + JSON.stringify(row));
    }
};

function operateFormatter(value, row, index) {
	
	var checked = "";
	if(row.false_positive != "0"){
		checked = "checked";
	}
	else{
		checked = "";
	}
	// console.log(checked);
	return [
	    '<a class="like" href="javascript:void(0)" >',
		    '<label class="switch">',
			  '<input style="width:24px" type="checkbox"'+checked+'>',
			  '<span class="slider"></span>',
			'</label>',
	    '</a>'
	].join('');
}

function get_services(ip){
    var url = "/server.php?type=external&level=3&category=services&"+ip;
    $.getJSON(url,function(data1){
    	services_data = data1;
    	$("#ip_val").text(data1[0].ip);
    	$("#domain_val").text(data1[0].domain);
    	delete data1[0]['_id'];
    	delete data1[0]['md5'];

    	var data = "text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data1));
    	$('<a href="data:' + data + '" download="data.json"><button class="btn btn-info">Export Json Data</button></a>').appendTo('#export_services');

    	var data = [];
    	for(k in data1[0]){
    		if (k != "ip" && k != 'domain'){
				var new_data = {};
				new_data['port'] = k;
				new_data['false_positive'] = data1[0][k]['false_positive'];
				new_data['version'] = data1[0][k]['version'];
				new_data['ip'] = data1[0]['ip'];
				data.push(new_data);
    		}
    	}
    	// console.log(data);
	    	
    	$('#services-table').bootstrapTable({
		    data: data,
		    columns: [{
		        field: 'port',
		        title: 'Port',
		        valign: 'middle',
		        sortable: sortable,
		        align: "center"
		    },{
		        field: 'version',
		        title: 'Version',
		        valign: 'middle',
		        sortable: sortable
		    },{
		        field: 'false_positive',
		        title: 'False Positive',
		        valign: 'middle',
		        events: service_fp,
		        formatter: operateFormatter,
		        align: "center"
		    }],
		    sidePagination: "client"
		});
    });	
}

function get_technologies(ip){
    var url = "/server.php?type=external&level=3&category=technologies&"+ip;
    $.getJSON(url,function(data1){
    	tech_data = data1;

    	delete data1[0]['_id'];
    	delete data1[0]['md5'];    	
    	
    	var data = "text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(data1));
    	$('<a href="data:' + data + '" download="data.json"><button class="btn btn-info">Export Json Data</button></a>').appendTo('#export_tech');

    	var data = [];
    	for(k in data1[0]){
    		if (k != "ip" && k != 'domain'){
				var new_data = {};
                if (typeof(data1[0][k]) == 'string')
                        new_data = {};
                else
                        new_data = data1[0][k];

                if (new_data['highest_cvss'] === undefined)
                    new_data['highest_cvss'] = 0;

                if (new_data['cves'] === undefined)
                    new_data['cves'] = [];

                if (new_data['version'] === undefined)
                    new_data['version'] = '-';

                if (new_data['false_positive'] === undefined)
                    new_data['false_positive'] = 0;

				new_data['tech'] = k;
				new_data['ip'] = data1[0]['ip'];
				data.push(new_data);
    		}
    	}
    	// console.log(data);
    	tech_data = data;
	    
	    var i=0;
    	$('#tech-table').bootstrapTable({
		    data: data,
		    columns: [{
		        field: 'tech',
		        title: 'Technology',
		        valign: 'middle',
		        sortable: sortable,
		        align: "left"
		    },{
		        field: 'version',
		        title: 'Version',
		        valign: 'middle',
		        sortable: sortable
		    },{
		        field: 'cves',
		        title: 'CVE Count',
		        valign: 'middle',
		        sortable: sortable,
		        align: "center",
		        formatter: function ( data, type, row ) 
        		{
    				i=i+1;					
        			if (data.length == 0){
        				return data.length;
        			}
    				return '<a href="#" onclick="show_cves('+i+')" id="myBtn" class="btn btn-primary btn-sm" data-toggle="modal" data-target="#myModal" >'+data.length+"</a>";
                }
		    },{
		        field: 'highest_cvss',
		        title: 'Highest Cvss',
		        valign: 'middle',
		        sortable: sortable
		    },{
		        field: 'false_positive',
		        title: 'False Positive',
		        valign: 'middle',
		        events: tech_fp,
		        formatter: operateFormatter,
		        align: "center"
		    }],
		    sidePagination: "client"
		});
    });	
}

function show_cves(i){
	// console.log(tech_data[i-1].cves);
	$("#cve_table").bootstrapTable({
		data:tech_data[i-1].cves,
		columns: [{
			field: 'id',
			title: 'CVE',
			valign: 'middle',
			align: "center",
			sortable: sortable,
			formatter: function ( data, type, row ) 
        		{
    				return '<a href="http://web.nvd.nist.gov/view/vuln/detail?vulnId='+data+'">'+data+"</a>";
                }
		},{
			field: 'cvss',
			title: 'CVSS',
			valign: 'middle',
			align: "center",
			sortable: sortable
		}]
	});

	$("#cve_table").bootstrapTable("load",tech_data[i-1].cves);
	$('#export_csv').click(function(){
         JSONToCSVConvertor(tech_data[i-1].cves, "CVE's", true);
     });
}

function get_web_vulns(ip){
    var url = "/server.php?type=external&level=3&category=vulnerabilities&"+ip;
    $.getJSON(url,function(data1){
		services_data = data1;

    	$('#web-table').bootstrapTable({
		    data: data1,
		    columns: [{
		        field: 'wapiti',
		        title: 'Wapiti',
		        valign: 'middle',
		        align: "center",
		        formatter: function ( data, type, row ) 
        		{
    				return '<a href="'+data+'" id="myBtn" class="btn btn-primary btn-sm"> Download Report </a>';
                }
		    },{
		        field: 'skipfish',
		        title: 'Skipfish',
		        valign: 'middle',
		        align: "center",
		        formatter: function ( data, type, row ) 
        		{
    				return '<a href="'+data+'" id="myBtn" class="btn btn-primary btn-sm"> Download Report </a>';
                }
		    }]
		});
    });	
}

function fill_bar_chart(ip){
	var url="/server.php?type=external&level=3&category=bargraphdata&"+ip;
    $.getJSON(url,function(data1){
		var colors = [
		     '#d9534f', //red
		     '#337ab7'	//light blue
		   ]

	    Highcharts.chart('container', {
		    chart: {
		        type: 'column',
		    	backgroundColor: "BLACK",
		    	height: "300px"
		    },
		    colors: colors,
		    title: {
		        text: 'IP Analysis',
		        align: "left",
		        style: {
		        	color: 'WHITE'
		        }
		    },
		    xAxis: {
		        categories: [
		            'Port Count',
		            'Tech Count',
		            'Critical cve\'s',
		            'High cve\'s',
		            'Medium cve\'s',
		            'Low cve\'s'
		        ],
		        crosshair: true,
		        labels: {
					style: {
						color: 'WHITE'
					}
				}
		    },
		    yAxis: {
		        min: 0,
		        title: false,
		        labels: {
		        	style: {
		        		color: "WHITE"
		        	}
		        }
		    },
		    tooltip: {
		        headerFormat: '<span style="font-size:10px">{point.key}</span><table>',
		        pointFormat: '<tr><td style="color:{series.color};padding:0">{series.name}: </td>' +
		            '<td style="padding:0">{point.y:.1f}</td></tr>',
		        footerFormat: '</table>',
		        shared: true,
		        useHTML: true
		    },
		    plotOptions: {
		        column: {
		            pointPadding: 0.2,
		            borderWidth: 0
		        }
		    },
	        legend: {
				itemStyle: {
					color: '#E0E0E3'
				},
				itemHoverStyle: {
					color: '#FFF'
				},
				itemHiddenStyle: {
					color: '#606063'
				},
				align: 'right',
        		verticalAlign: 'top',
        		floating: true,
        		x: -30
        		
			},
		    series: [{
		        name: 'Count',
		        data: [
		        	data1['port_count'][0],
		        	data1['tech_count'][0],
		        	data1['critical_cve_count'][0],
		        	data1['high_cve_count'][0],
		        	data1['medium_cve_count'][0],
		        	data1['low_cve_count'][0]
		        ]
		    },{
		    	name: 'False Positives',
		    	data: [
		    		data1['port_count'][1],
		        	data1['tech_count'][1],
		        	data1['critical_cve_count'][1],
		        	data1['high_cve_count'][1],
		        	data1['medium_cve_count'][1],
		        	data1['low_cve_count'][1]
		    	]
		    }],
			sidePagination: "client"
		});
   });
}
