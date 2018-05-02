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
from xml.dom.minidom import Document
from wapitiCore.report.reportgenerator import ReportGenerator


class XMLReportGenerator(ReportGenerator):
    """
    This class generates a report with the method printToFile(fileName) which contains
    the information of all the vulnerabilities notified to this object through the
    method logVulnerability(vulnerabilityTypeName,level,url,parameter,info).
    The format of the file is XML and it has the following structure:
    <report type="security">
        <generatedBy id="Wapiti 2.3.0"/>
        <vulnerabilityTypeList>
            <vulnerabilityType name="SQL Injection">

        <vulnerabilityTypeList>
            <vulnerabilityType name="SQL Injection">
                <vulnerabilityList>
                    <vulnerability level="3">
                        <url>http://www.a.com</url>
                        <parameters>id=23</parameters>
                        <info>SQL Injection</info>
                    </vulnerability>
                </vulnerabilityList>
            </vulnerablityType>
        </vulnerabilityTypeList>
    </report>
    """

    __xmlDoc = None
    __infos = {}
    __flawTypes = {}

    __vulns = {}
    __anomalies = {}

    __infos = {}

    def __init__(self):
        self.__xmlDoc = Document()

    def setReportInfo(self, target, scope=None, date_string="", version=""):
        self.__infos["target"] = target
        self.__infos["date"] = date_string
        self.__infos["version"] = version
        if scope:
            self.__infos["scope"] = scope

    # Vulnerabilities
    def addVulnerabilityType(self, name,
                             description="",
                             solution="",
                             references={}):
        if name not in self.__flawTypes:
            self.__flawTypes[name] = {'desc': description,
                                      'sol': solution,
                                      'ref': references}
        if name not in self.__vulns:
            self.__vulns[name] = []

    def logVulnerability(self,
                         category=None,
                         level=0,
                         request=None,
                         parameter="",
                         info=""):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        vuln_dict = {"method": request.method,
                     "path": request.file_path,
                     "info": info,
                     "level": level,
                     "parameter": parameter,
                     "http_request": request.http_repr,
                     "curl_command": request.curl_repr,
                     }
        if category not in self.__vulns:
            self.__vulns[category] = []
        self.__vulns[category].append(vuln_dict)

    # Anomalies
    def addAnomalyType(self, name,
                       description="",
                       solution="",
                       references={}):
        if name not in self.__flawTypes:
            self.__flawTypes[name] = {'desc': description,
                                      'sol': solution,
                                      'ref': references}
        if name not in self.__anomalies:
            self.__anomalies[name] = []

    def logAnomaly(self,
                   category=None,
                   level=0,
                   request=None,
                   parameter="",
                   info=""):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        anom_dict = {"method": request.method,
                     "path": request.file_path,
                     "info": info,
                     "level": level,
                     "parameter": parameter,
                     "http_request": request.http_repr,
                     "curl_command": request.curl_repr,
                     }
        if category not in self.__anomalies:
            self.__anomalies[category] = []
        self.__anomalies[category].append(anom_dict)

    def generateReport(self, fileName):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with
        the method logVulnerability(vulnerabilityTypeName,level,url,parameter,info)
        """

        report = self.__xmlDoc.createElement("report")
        report.setAttribute("type", "security")
        self.__xmlDoc.appendChild(report)

        # Add report infos
        report_infos = self.__xmlDoc.createElement("report_infos")
        generatorName = self.__xmlDoc.createElement("info")
        generatorName.setAttribute("name", "generatorName")
        generatorName.appendChild(self.__xmlDoc.createTextNode("wapiti"))
        report_infos.appendChild(generatorName)

        generatorVersion = self.__xmlDoc.createElement("info")
        generatorVersion.setAttribute("name", "generatorVersion")
        generatorVersion.appendChild(self.__xmlDoc.createTextNode(self.__infos["version"]))
        report_infos.appendChild(generatorVersion)

        scope = self.__xmlDoc.createElement("info")
        scope.setAttribute("name", "scope")
        scope.appendChild(self.__xmlDoc.createTextNode(self.__infos["scope"]))
        report_infos.appendChild(scope)

        dateOfScan = self.__xmlDoc.createElement("info")
        dateOfScan.setAttribute("name", "dateOfScan")
        dateOfScan.appendChild(self.__xmlDoc.createTextNode(self.__infos["date"]))
        report_infos.appendChild(dateOfScan)
        report.appendChild(report_infos)

        vulnerabilities = self.__xmlDoc.createElement("vulnerabilities")
        anomalies = self.__xmlDoc.createElement("anomalies")

        # Loop on each flaw classification
        for flawType in self.__flawTypes:
            container = None
            classification = ""
            flaw_dict = {}
            if flawType in self.__vulns:
                container = vulnerabilities
                classification = "vulnerability"
                flaw_dict = self.__vulns
            elif flawType in self.__anomalies:
                container = anomalies
                classification = "anomaly"
                flaw_dict = self.__anomalies

            # Child nodes with a description of the flaw type
            flawTypeNode = self.__xmlDoc.createElement(classification)
            flawTypeNode.setAttribute("name", flawType)
            flawTypeDesc = self.__xmlDoc.createElement("description")
            flawTypeDesc.appendChild(self.__xmlDoc.createCDATASection(self.__flawTypes[flawType]['desc']))
            flawTypeNode.appendChild(flawTypeDesc)
            flawTypeSolution = self.__xmlDoc.createElement("solution")
            flawTypeSolution.appendChild(self.__xmlDoc.createCDATASection(self.__flawTypes[flawType]['sol']))
            flawTypeNode.appendChild(flawTypeSolution)

            flawTypeReferences = self.__xmlDoc.createElement("references")
            for ref in self.__flawTypes[flawType]['ref']:
                referenceNode = self.__xmlDoc.createElement("reference")
                titleNode = self.__xmlDoc.createElement("title")
                urlNode = self.__xmlDoc.createElement("url")
                titleNode.appendChild(self.__xmlDoc.createTextNode(ref))
                url = self.__flawTypes[flawType]['ref'][ref]
                urlNode.appendChild(self.__xmlDoc.createTextNode(url))
                referenceNode.appendChild(titleNode)
                referenceNode.appendChild(urlNode)
                flawTypeReferences.appendChild(referenceNode)
            flawTypeNode.appendChild(flawTypeReferences)

            # And child nodes with each flaw of the current type
            entriesNode = self.__xmlDoc.createElement("entries")
            for flaw in flaw_dict[flawType]:
                entryNode = self.__xmlDoc.createElement("entry")
                methodNode = self.__xmlDoc.createElement("method")
                methodNode.appendChild(self.__xmlDoc.createTextNode(flaw["method"]))
                entryNode.appendChild(methodNode)
                pathNode = self.__xmlDoc.createElement("path")
                pathNode.appendChild(self.__xmlDoc.createTextNode(flaw["path"]))
                entryNode.appendChild(pathNode)
                levelNode = self.__xmlDoc.createElement("level")
                levelNode.appendChild(self.__xmlDoc.createTextNode(str(flaw["level"])))
                entryNode.appendChild(levelNode)
                parameterNode = self.__xmlDoc.createElement("parameter")
                parameterNode.appendChild(self.__xmlDoc.createTextNode(flaw["parameter"]))
                entryNode.appendChild(parameterNode)
                infoNode = self.__xmlDoc.createElement("info")
                infoNode.appendChild(self.__xmlDoc.createTextNode(flaw["info"]))
                entryNode.appendChild(infoNode)
                httpRequestNode = self.__xmlDoc.createElement("http_request")
                httpRequestNode.appendChild(self.__xmlDoc.createCDATASection(flaw["http_request"]))
                entryNode.appendChild(httpRequestNode)
                curlCommandNode = self.__xmlDoc.createElement("curl_command")
                curlCommandNode.appendChild(self.__xmlDoc.createCDATASection(flaw["curl_command"]))
                entryNode.appendChild(curlCommandNode)
                entriesNode.appendChild(entryNode)
            flawTypeNode.appendChild(entriesNode)
            container.appendChild(flawTypeNode)
        report.appendChild(vulnerabilities)
        report.appendChild(anomalies)

        f = open(fileName, "w")
        try:
            f.write(self.__xmlDoc.toprettyxml(indent="    ", encoding="UTF-8"))
        finally:
            f.close()


if __name__ == "__main__":

    SQL_INJECTION = "Sql Injection"
    FILE_HANDLING = "File Handling"
    XSS = "Cross Site Scripting"
    CRLF = "CRLF Injection"
    EXEC = "Commands execution"

    try:
        xmlGen = XMLReportGenerator()
        xmlGen.addVulnerabilityType(SQL_INJECTION)
        xmlGen.addVulnerabilityType(FILE_HANDLING)
        xmlGen.addVulnerabilityType(XSS)
        xmlGen.addVulnerabilityType(CRLF)
        xmlGen.addVulnerabilityType(EXEC)
        xmlGen.logVulnerability("SQL Inyection", "1", "url1", "parameter1", "info1")
        xmlGen.logVulnerability("SQL Inyection", "2", "url2", "parameter2", "info2")
        xmlGen.logVulnerability("SQL Inyection", "2", "url3", "parameter3", "info3")
        xmlGen.logVulnerability("SQL Inyection", "3", "url4", "parameter4", "info4")
        xmlGen.logVulnerability("Cross Site Scripting", "3", "url5", "parameter5", "info5")
        xmlGen.logVulnerability("Cross Site Scripting", "3", "url6", "parameter6", "info6")
        xmlGen.logVulnerability("Cross Site Scripting", "2", "url7", "parameter7", "info7")
        xmlGen.logVulnerability("Cross Site Scripting", "1", "url8", "parameter8", "info8")
        xmlGen.logVulnerability("Google Hacking", "2", "url9", "parameter9", "info9")
        xmlGen.printToFile("sampleReport.xml")
    except SystemExit:
        pass
