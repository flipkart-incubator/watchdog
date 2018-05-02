<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
    <style>
      body, td {
        font-family:Arial;
        font-size:12px;
        color:#404040;
      }
      .report .screenshot img {
        width:500px;
        height:300px;
        padding-right:50px;
      }

      .report {
        padding-bottom:50px;
        page-break-after:always;
      }

      .field {
        text-align: right;
        color: #A0A0A0;
        padding-right:15px;
      }

      table { padding-bottom:50px; }
  </style>
  </head>
  <body>
<?php

$inputFile = $argv[1];

//<img src="//chart.googleapis.com/chart?chs=300x150&cht=p&chco=F40009&chd=t:10,20,30,40,50,60,70,80,90&chp=0.395&chl=JavaScript|Flash|Style+Sheet|HTML|Video|Audio|Image|Data|Other" width="300" height="150" alt="" />

$data = json_decode(file_get_contents($inputFile));

foreach ($data as $index => $site ) {
   if  ( empty($site->imageName) ) {
     continue;
   }
   print '<div class="report">' .
         ' <table><tr>' .
         '  <td valign="top"><div class="screenshot"><img src="' . $site->imageName . '"/></div></td>' .
         '  <td>' .
         '    <table>';

   print "<tr><td class=\"field\"><b>Name</b></td><td><b>" . $site->name . "</b></td></tr>";
   print "<tr><td class=\"field\">Page Title</td><td>" . $site->title . "</td></tr>";
   print "<tr><td class=\"field\">URL</td><td>"   . $site->url . "</td></tr>";
   print "<tr><td class=\"field\">Resolved URL</td><td>" . $site->resolvedUrl . "</td></tr>";
   print "<tr><td class=\"field\">Page Load Time (millis)</td><td>" . $site->pageLoadTime . "</td></tr>";

   foreach ( $site->detected as $i => $app ) {
     print "<tr><td class=\"field\">$app</td><td><img src=\"../wappalyzer/icons/" . $app . ".png\"/></td></tr>";
   }

   $resourceData = array();
   $resourceLabels = array();
   foreach ( $site->resourceTypes as $category => $size ) {
     $resourceLabels[]= $category;
     $resourceData[]= $site->resourceTypes->$category;
   }
   $resourceImg = '<img src="http://chart.googleapis.com/chart?chs=300x150&cht=p&chco=F40009&chd=t:' .
                  implode(',', $resourceData) . 
                  '&chp=0.395&chl=' .
                  implode('|', $resourceLabels) . 
                  '" width="300" height="150" alt="" />';
   print "<tr><td class=\"field\">Resource Breakdown</td></tr>";
   print '<tr><td colspan="2">' . $resourceImg . '</td></tr>';

   print 
         '    </table>' .
         '  </td>' .
         ' </tr></table>' .
         '</div>';
}

?>
  </body>
</html>
