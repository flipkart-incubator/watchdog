#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2013 Nicolas Surribas
#
# Original authors :
# Alberto Pastor
# David del Pozo
# Copyright (C) 2008 Informatica Gesfor
# ICT Romulus (http://www.ict-romulus.eu)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import os
from wapitiCore.report.jsonreportgenerator import JSONReportGenerator
from shutil import copytree, rmtree
import sys


class HTMLReportGenerator(JSONReportGenerator):
    """
    This class generates a Wapiti scan report in HTML format.
    It first generates a JSON report and insert in the HTML template.
    For more information see JSONReportGenerator class
    Then it copies the template structure (which js and css files) in the output directory.
    """
    if hasattr(sys, "frozen"):
        BASE_DIR = os.path.join(os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding())), "data")
    else:
        BASE_DIR = os.path.dirname(sys.modules['wapitiCore'].__file__)
    REPORT_DIR = "report_template"
    REPORT_JSON_FILE = "vulnerabilities.json"

    def generateReport(self, fileName):
        """
        Copy the report structure in the specified 'fileName' directory
        If these path exists, it will be overwritten
        """
        if os.path.exists(fileName):
            rmtree(fileName)
        copytree(os.path.join(self.BASE_DIR, self.REPORT_DIR), fileName)

        JSONReportGenerator.generateReport(self, os.path.join(fileName, self.REPORT_JSON_FILE))
        fd = open(os.path.join(fileName, self.REPORT_JSON_FILE))
        json_data = fd.read()
        json_data = json_data.replace('</', r'<\/')
        fd.close()

        fd = open(os.path.join(fileName, "index.html"), "r+")
        html_data = fd.read()
        html_data = html_data.replace('__JSON_DATA__', json_data)
        fd.seek(0)
        fd.truncate(0)
        fd.write(html_data)
        fd.close()

if __name__ == "__main__":

    SQL_INJECTION = "Sql Injection"
    FILE_HANDLING = "File Handling"
    XSS = "Cross Site Scripting"
    CRLF = "CRLF Injection"
    EXEC = "Commands execution"
#
#    try:
#        xmlGen = HTMLReportGenerator()
#        xmlGen.addVulnerabilityType(SQL_INJECTION)
#        xmlGen.addVulnerabilityType(FILE_HANDLING)
#        xmlGen.addVulnerabilityType(XSS)
#        xmlGen.addVulnerabilityType(CRLF)
#        xmlGen.addVulnerabilityType(EXEC)
#        xmlGen.logVulnerability("SQL Inyection", "1", "url1", "parameter1", "info1")
#        xmlGen.logVulnerability("SQL Inyection", "2", "url2", "parameter2", "info2")
#        xmlGen.logVulnerability("SQL Inyection", "2", "url3", "parameter3", "info3")
#        xmlGen.logVulnerability("SQL Inyection", "3", "url4", "parameter4", "info4")
#        xmlGen.logVulnerability("Cross Site Scripting", "3", "url5", "parameter5", "info5")
#        xmlGen.logVulnerability("Cross Site Scripting", "3", "url6", "parameter6", "info6")
#        xmlGen.logVulnerability("Cross Site Scripting", "2", "url7", "parameter7", "info7")
#        xmlGen.logVulnerability("Cross Site Scripting", "1", "url8", "parameter8", "info8")
#        xmlGen.logVulnerability("Google Hacking", "2", "url9", "parameter9", "info9")
#        """xmlGen.printToFile("sampleReport.xml")"""
#	xmlGen.generateReport("hola")
#
#    except SystemExit:
#        pass
#
#
