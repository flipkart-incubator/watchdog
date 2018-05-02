var fs = require('fs');
var U  = require('underscore');
var path = require('path');
var csv = require('finite-csv');
var program = require('commander');

program
  .version('0.0.1')
  .option('-d, --dataDir <path>', 'Data directory')
  .option('-x, --regexFile <path>', 'Regex file path')
  .option('-c, --csvFile <path>', 'CVS file containing site list')
  .option('-m, --maxRows [count]', 'Max number of records to process.', parseInt, 100000)
  .option('-u, --urlColumn <name>', 'Max number of records to process.', 'url')
  .parse(process.argv);

//console.log(program);
//console.log('foo usage=' + program.usage);
if ( program.dataDir == undefined || program.regexFile == undefined || program.csvFile == undefined ) {
  program.help();
}

/* process the data directory */
if ( ! (fs.existsSync(program.dataDir) && fs.lstatSync(program.dataDir).isDirectory() ) ) {
  console.error('directory ' + program.dataDir + ' does not exist or is not a directory');
  process.exit(1);
}
var files = fs.readdirSync(program.dataDir);

/* process the regex file */
if ( ! fs.existsSync(program.regexFile) ) {
  console.error('json regex file ' + program.regexFile + ' does not exist');
  process.exit(1);
}
var regexFile = fs.readFileSync(program.regexFile, 'utf8');
var regexObj = null;
try {
  regexObj = JSON.parse(regexFile);
} catch (msg) {
  console.error("json regex file " + program.regexFile + " was not valid JSON.  Check out JSON lint online to validate it.");
  process.exit(1);
}

/* process the csv file */
if ( ! fs.existsSync(program.csvFile) ) {
  console.error('CSV file ' + program.csvFile + ' does not exist');
  process.exit(1);
}
var csvFile = fs.readFileSync(program.csvFile, 'utf8');
csvFile = csvFile.replace(/\cm[\r\n]*/g, "\n");

var sites = [];
try {
  //var csvRecs = csv.parseCSV("a,b,c\n1,2,3");
  var records = csv.parseCSV(csvFile);

  var skipRows = -1;
  /* let's look for the header.  the header is the first row that contains a column with the urlColumn in it */
  outer:
  for ( var rI = 0; rI < records.length; rI++ ) {
    var record = records[rI];
    for ( var cI = 0; cI < record.length; cI++ ) {
      if ( record[cI] == program.urlColumn ) {
        skipRows = rI;
        break outer;
      }
    }
  }

  if ( skipRows < 0 ) {
    throw "Unable to find a row in the data with a column matching " + program.urlColumn;
  }

  sites = csv_to_obj(records.slice(skipRows));
  //console.log(sites);
  //console.log(sites[0]);
  sites = sites.slice(0,program.maxRows);
} catch (msg) {
  console.error("csv file " + program.csvFile + " was not valid CSV. " + msg);
  console.log(msg.stack);
  process.exit(1);
}

//console.log("site count=" + sites.length);

var rows = [];

for ( var i = 0; i < sites.length; i++ ) {
  var site = sites[i];
  //console.log("record [" + i + "] ", site[' URL ' ]);
  var file = U.filter(files, function(entry) {
    // the i+1 is due to a bug in the crawler
    return entry.indexOf('site_' + (i+1) + '_') == 0 && entry.match(/\.txt$/i);
  });

  var row = [];
  if ( file.length > 0 ) {
    var fullPath = program.dataDir + path.sep + file[0];
    var infile = fs.readFileSync(program.dataDir + path.sep + file[0], 'utf8');
    for (var key in regexObj) {
      var def = regexObj[key];
      var exp = new RegExp(def.pattern, def.modifiers);
      var match = infile.match(exp);
      var result = "";
      //console.log("checking " + def.pattern + ", match=", match);
      if ( match ) {
        result = match[0];
        //console.log('KEY=' + key);
        if ( def.hit != undefined ) {
          result = def.hit;
          for (var k = 0; k < match.length; k++ ) {
            result = result.replace('\{\{' + k + '\}\}', match[k]);
          }
        }
        result = result.replace('\{\{count\}\}', match.length);
        //console.log('output=' + result);
      } else {
        if ( def.miss != undefined ) {
          result = def.miss;
        }
      }
      row.push(result);
      //console.log(result + " == " + key);
    }
    //console.log("processing file " + files[0]);
  } else {
    for ( var key in regexObj) {
      row.push("");
    }
    //console.log("no file found for site_" + (i+1) + "_...");
  }
  rows.push(row);
  //console.log('res=', row);
}

for ( var r = 0; r < rows.length; r++ ) {
  for ( var c = 0; c < rows[r].length; c++ ) {
    /* i'm going to remove all carriage returns here */
    rows[r][c] = rows[r][c].replace(/[\r\n]/g, " ");
    /* if we see a double quote then we will wrap the whole column with quotes and escape the quotes within */
    if ( rows[r][c].match(/[",]/) ) {
      rows[r][c] = '"' + rows[r][c].replace(/"/g, '""') + '"';
    }
  }
  rows[r] = rows[r].join(',');
}

rows.unshift(U.keys(regexObj));
console.log(rows.join("\n"));

/**
 * This awesome function will return an
 * array of rows with the key values of
 * each row matching the column header
 * which should be provided in the first row.
 */
function csv_to_obj(records) {
  var objects = [];
  var header = [];
  for ( var i = 0; i < records.length; i++ ) {
    var values = records[i];
    if ( i == 0 ) {
      header = values;
    } else {
      var item = [];
      for ( var recI = 0; recI < header.length; recI++ ) {
	item[header[recI]] = recI < values.length ? values[recI] : "";
      }
      objects.push(item);
    }
  }
  return objects;
}

function escapeRegExp(str) {
  return str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, "\\$&");
}

