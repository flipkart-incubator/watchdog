<!DOCTYPE html>
<html lang="en">
<head>
  <title>Watch Dog</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="/favicon.ico" type="image/gif" sizes="16x16">
  
  <link rel="stylesheet" href="/static/css/bootstrap.min.css">
  <script src="https://code.jquery.com/jquery-1.12.4.js"></script>
  <script src="/static/js/bootstrap.min.js"></script>
  <script src="/static/js/highcharts.js"></script>
  <script src="/static/js/exporting.js"></script>
  <script src="/static/js/ip_analysis.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.0/bootstrap-table.min.js"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.0/bootstrap-table.min.css" rel="stylesheet" type="text/css" />
  <link href="/static/css/ip_analysis.css" rel="stylesheet" type="text/css" />
  <script src="/static/js/common.js"></script>
</head>
<body>

<nav class="navbar navbar-inverse">
  <div class="container-fluid">
    <div class="navbar-header" style="padding-left: 20px">
      <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#myNavbar">
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>                        
      </button>
      <a class="navbar-brand" href="/index.php" style="margin:-12px 0px 0px -40px;" data-reactid=".0.0.0.0.0.0">
        <img height="43px" width="43px" src="/static/images/watchdog.png" data-reactid=".0.0.0.0.0.0.0">
      </a>
      <a class="navbar-brand" href="/index.php">
        Watch Dog
      </a>
    </div>
    <div class="collapse navbar-collapse" id="myNavbar">
      <ul class="nav navbar-nav">
        <li><a href="/index.php">Home</a></li>
        <li class="active"><a href="/External">External Assets</a></li>
      </ul>
    </div>
  </div>
</nav>
<br/>
<div class="col-sm-12 table_content">
  <div>
    <div class="col-md-1">
      <img class="ip_img" src="/static/images/ip.png" height="60px" width="60px" alt="">
    </div>
    <div class="col-md-11 ip_domain">
      <h2 id="ip_val"></h2>
      <h2 id="domain_val"></h2>
    </div>
  </div>
  <div id="container"></div>
</div>
<div class="col-sm-12 table_content">
    <ul class="nav nav-tabs">
    <li class="active"><a data-toggle="tab" href="#services">Services</a></li>
    <li><a data-toggle="tab" href="#tech">Technologies</a></li>
    <li><a data-toggle="tab" href="#web">Web Vulnerabilties</a></li>
  </ul>
  <br/>
    <div class="tab-content">
      <div id="services" class="tab-pane fade in active" style="width: 40%; margin-left: 25%">
        <div id="export_services"></div><br/>
        <table id='services-table' data-pagination="true"></table>
      </div>
      <div id="tech" class="tab-pane fade" style="width: 60%; margin-left: 20%">
        <div id="export_tech"></div><br/>
        <div id="pop">
          <div class="modal fade" id="myModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                         <h4 class="modal-title" id="myModalLabel">CVEs</h4>
                    </div>
                    <div class="modal-body">
                      <button type="button" class="btn btn-info" onclick="download_ips()">Export to csv</button><br/><br/>
                      <table id="cve_table"></table>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
          </div>
        </div>
        <table id='tech-table' data-pagination="true"></table>
      </div>
      <div id="web" class="tab-pane fade" style="width: 40%; margin-left: 25%">
        <br/>
        <table id='web-table' data-pagination="true"></table>
      </div>
  </div>

</div>
<br/><br/>
<footer class="container-fluid">
  <div class="footer-copyright py-3 text-center">
      Contant @ <a href="mailto:security@flipkart.com"> Flipkart Security </a>
  </div>
</footer>

</body>
</html>
