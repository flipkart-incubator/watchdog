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
  <script src="/static/js/uniqueCriticalVul.js"></script>
  <script src="/static/js/common.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.0/bootstrap-table.min.js"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.10.0/bootstrap-table.min.css" rel="stylesheet" type="text/css" />
  <link href="/static/css/external.css" rel="stylesheet" type="text/css" />
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
  <h2>Unique Critical Vulnerabilities</h2>
  <button class="btn btn-info" onclick="download_cves()" >Export to csv</button><br/><br/>
  <table id="table" data-pagination="true"></table>
  <div id="pop">
    <div class="modal fade" id="myModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
      <div class="modal-dialog">
          <div class="modal-content">
              <div class="modal-header">
                  <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                   <h4 class="modal-title" id="myModalLabel">CVEs</h4>
              </div>
              <div class="modal-body">
                <button type="button" id="download_ips" class="btn btn-info" onclick="download_ips()">Export to csv</button><br/><br/>
                <table id="unique_table"></table>
              </div>
              <div class="modal-footer">
                  <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
              </div>
          </div>
      </div>
    </div>
  </div>
</div>
<br/><br/>
<footer class="container-fluid">
  <div class="footer-copyright py-3 text-center">
      Contact @ <a href="mailto:security@flipkart.com"> Flipkart Security </a>
  </div>
</footer>

</body>
</html>
