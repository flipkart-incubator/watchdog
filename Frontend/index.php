<!DOCTYPE html>
<html lang="en">
<head>
  <title>Watch Dog</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="/favicon.ico" type="image/gif" sizes="16x16">
  
  <link rel="stylesheet" href="/static/css/bootstrap.min.css">
  <script src="/static/js/jquery.min.js"></script>
  <script src="/static/js/bootstrap.min.js"></script>
  <script src="/static/js/highcharts.js"></script>
  <script src="/static/js/exporting.js"></script>
  <script src="/static/js/index.js"></script>
  <link href="/static/css/index.css" rel="stylesheet" type="text/css" />
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
      <a class="navbar-brand" href="#" style="margin:-12px 0px 0px -40px;" data-reactid=".0.0.0.0.0.0">
        <img height="43px" width="43px" src="/static/images/watchdog.png" data-reactid=".0.0.0.0.0.0.0">
      </a>
      <span class="navbar-brand" href="#">
        Watch Dog
      </span>
    </div>
    <div class="collapse navbar-collapse" id="myNavbar">
      <ul class="nav navbar-nav">
        <li class="active"><a href="#">Home</a></li>
        <li><a href="/External">External Assets</a></li>
      </ul>
    </div>
  </div>
</nav>
  
<div class="container-fluid bg-4 text-center">
  <div class="row no-gutter">
    <div class="columns col-sm-3">
      <div class="img-responsive row-ele row-heading" alt="Total IP Count">
        Total IPs Scanned<br/>
        <a href="/External"><span id="ipCount" class="row-heading-value"></span></a>
      </div>
    </div>
    <div class="columns col-sm-4"> 
      <div class="img-responsive row-ele row-heading" alt="Unique CVEs">
        Vulnerabilities Identified<br/>
        <a href="/External/uniqueVul.php"><span id="uniqueCVE" class="row-heading-value"></span></a>
      </div>
    </div>
    <div class="columns col-sm-5"> 
      <div class="img-responsive row-ele row-heading" alt="High Severity Issues">
        High Severity Issues<br/><br/>
        <div class="col-sm-3">
          <table class="high-severe">
            <tr>
              <th>Critical</th><th>&nbsp;</th>
              <th>High</th>
            </tr>
            <tr style="font-size: 40px; font-family: 'Roboto Condensed'">
              <td><a href="/External/uniqueCriticalVuls.php" id="critical"></td></a>
              <th>&nbsp;</th>
              <td><a href="/External/uniqueHighVuls.php" id="high"></td>
            </tr>
          </table>
        </div>
        <div class="col-sm-9 pull-right" style="height: 250px">
          <div id="container"></div>
        </div>
      </div>
    </div>
  </div>
</div><br>

<div class="container-fluid bg-3 text-center">
  <div class="row second-row no-gutter">
    <div class="columns col-sm-6"> 
      <div class="img-responsive row-ele row-heading" alt="High Severity Issues">
        Most Used Front End Tech<br/>
        <a href="/External/techDetails.php" >
          <div class="col-sm-2" id="tech_stack"></div>
        </a>
        <div class="col-sm-4 pull-right tech_stack_chart">
          <div id="container2"></div>
        </div>
      </div>
    </div>
    <div class="columns col-sm-6"> 
      <div class="img-responsive row-ele row-heading" alt="High Severity Issues">
        Top Running Services<br/>
        <a href="/External/portDetails.php" >
          <div class="col-sm-2" id="top_services"></div>
        </a>
        <div class="col-sm-4 pull-right tech_stack_chart">
          <div id="container3"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<footer class="container-fluid">
  <div class="footer-copyright py-3 text-center">
      Contact @ <a href="mailto:security@flipkart.com"> Flipkart Security </a>
  </div>
</footer>

</body>
</html>
