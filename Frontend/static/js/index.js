$(document).ready(function(){
	var full_data = {}
    $.get("/server.php?type=external&level=1", function(data, status){
    	data = $.parseJSON(data);
    	full_data = data;

        $("#ipCount").text(data.ipCount);
        $("#uniqueCVE").text(data.uniqueCVE);
        $("#critical").text(data.uniqueHighSeverityExt[0].value);
        $("#high").text(data.uniqueHighSeverityExt[1].value);
        fill_pie_chart(data.uniqueHighSeverityExt,'container');
        fill_pie_chart(data.top3Tech,'container2');
        fill_pie_chart(data.topServices,'container3');
        fill_data_table(data.top3Tech,'tech_stack',['Tech','Usage']);
        fill_data_table(data.topServices,'top_services',['Port','IPs']);
    });

    function fill_pie_chart(data,id){
    	var new_data = [];
    	for (var i = 0; i < data.length; i++) {
    		new_data.push({'name': data[i].name,'y':data[i].value});
    	}
    	// console.log(new_data);

    	var colors = [
		     '#d9534f', //red
		     '#f0ad4e', //orange
		     '#337ab7',	//light blue
		     '#5cb85c',	//green
		     '#5bc0de'	//yellow
		   ]

    	Highcharts.chart(id, {
		    chart: {
		    	backgroundColor: "black",
		        plotBackgroundColor: null,
		        plotBorderWidth: null,
		        plotShadow: false,
		        type: 'pie'
		    },
		    title: {
		        text: false
		    },
		    tooltip: {
		        pointFormat: '{series.name}: <b>{point.percentage:.1f}%</b>'
		    },
		    plotOptions: {
		        pie: {
		            allowPointSelect: true,
		            cursor: 'pointer',
		            dataLabels: {
		                enabled: false
		            },
		            colors: colors,
		            showInLegend: true
		        }
		    },
		    legend:{
		    	itemStyle: {
		            color: '#FFFFFF',
		            fontWeight: 'bold'
		        }
		    },
		    series: [{
		        name: 'Brands',
		        colorByPoint: true,
		        data: new_data
		    }]
		});
    }

    function fill_data_table(data,id,headers){
	  var tech_stack = document.getElementById(id);
	  var tbl = document.createElement("table");
	  tbl.setAttribute('border','1');
	  var tblBody = document.createElement("tbody");

	  var tr = document.createElement("tr");
	  var cell1 = document.createElement("th");
	  cell1.setAttribute('style','width:200px');
  	  var cellText = document.createTextNode(headers[0]);
      cell1.appendChild(cellText);

	  var cell2 = document.createElement("th");
	  cellText = document.createTextNode(headers[1]);
      cell2.appendChild(cellText);

	  tr.appendChild(cell1);
	  tr.appendChild(cell2);
	  tblBody.appendChild(tr);

	  for (var i = 0; i < data.length; i++) {
	    var row = document.createElement("tr");
		var cell1 = document.createElement("td");
		var cell2 = document.createElement("td");

		var cellText = document.createTextNode(data[i].name);
	    cell1.appendChild(cellText);
	    row.appendChild(cell1);
		
		cellText = document.createTextNode(data[i].value);
		cell2.appendChild(cellText);
		row.appendChild(cell2);
 
	    tblBody.appendChild(row);
	  }
	 
	  tbl.appendChild(tblBody);
	  tech_stack.appendChild(tbl);
	  tbl.setAttribute('id',"tech-data-table");
	}
});
