#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2013 Nicolas Surribas
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
import uuid


class OpenVASReportGenerator(ReportGenerator):
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

    __vulnCount = 0
    __anomCount = 0

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
                     "hostname": request.hostname,
                     "port": request.port,
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
        self.__vulnCount += 1

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
                     "hostname": request.hostname,
                     "port": request.port,
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
        self.__anomCount += 1

    def generateReport(self, fileName):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with
        the method logVulnerability(vulnerabilityTypeName,level,url,parameter,info)
        """

        uuid_report = str(uuid.uuid1())
        report = self.__xmlDoc.createElement("report")
        report.setAttribute("extension", "xml")
        report.setAttribute("id", uuid_report)
        report.setAttribute("type", "scan")
        report.setAttribute("content_type", "text/html")
        report.setAttribute("format_id", "a994b278-1f62-11e1-96ac-406186ea4fc5")
        self.__xmlDoc.appendChild(report)

        # Add report infos
        report_infos = self.__xmlDoc.createElement("report")
        report_infos.setAttribute("id", uuid_report)

        scan_run_status = self.__xmlDoc.createElement("scan_run_status")
        scan_run_status.appendChild(self.__xmlDoc.createTextNode("Done"))
        report_infos.appendChild(scan_run_status)

        scan_start = self.__xmlDoc.createElement("scan_start")
        scan_start.appendChild(self.__xmlDoc.createTextNode(self.__infos["date"]))
        report_infos.appendChild(scan_start)

        results = self.__xmlDoc.createElement("results")
        results.setAttribute("start", "1")
        results.setAttribute("max", str(self.__vulnCount + self.__anomCount))

        # Loop on each flaw classification
        for flawType in self.__flawTypes:
            classification = ""
            flaw_dict = {}
            if flawType in self.__vulns:
                classification = "vulnerability"
                flaw_dict = self.__vulns
            elif flawType in self.__anomalies:
                classification = "anomaly"
                flaw_dict = self.__anomalies

            for flaw in flaw_dict[flawType]:
                result = self.__xmlDoc.createElement("result")
                result.setAttribute("id", str(uuid.uuid4()))

                subnet = self.__xmlDoc.createElement("subnet")
                subnet.appendChild(self.__xmlDoc.createTextNode(flaw["hostname"]))
                result.appendChild(subnet)

                host = self.__xmlDoc.createElement("host")
                host.appendChild(self.__xmlDoc.createTextNode(flaw["hostname"]))
                result.appendChild(host)

                port = self.__xmlDoc.createElement("port")
                port.appendChild(self.__xmlDoc.createTextNode(str(flaw["port"])))
                result.appendChild(port)

                nvt = self.__xmlDoc.createElement("nvt")
                nvt.setAttribute("oid", str(uuid.uuid4()))

                name = self.__xmlDoc.createElement("name")
                name.appendChild(self.__xmlDoc.createTextNode(flawType))
                nvt.appendChild(name)

                family = self.__xmlDoc.createElement("family")
                family.appendChild(self.__xmlDoc.createTextNode(classification))
                nvt.appendChild(family)

                cvss_base = self.__xmlDoc.createElement("cvss_base")
                cvss_base.appendChild(self.__xmlDoc.createTextNode("0.0"))
                nvt.appendChild(cvss_base)

                risk_factor = self.__xmlDoc.createElement("risk_factor")
                risk_factor.appendChild(self.__xmlDoc.createTextNode(str(flaw["level"])))
                nvt.appendChild(risk_factor)

                cve = self.__xmlDoc.createElement("cve")
                cve.appendChild(self.__xmlDoc.createTextNode(""))
                nvt.appendChild(cve)

                bid = self.__xmlDoc.createElement("bid")
                bid.appendChild(self.__xmlDoc.createTextNode(""))
                nvt.appendChild(bid)

                tags = self.__xmlDoc.createElement("tags")
                tags.appendChild(self.__xmlDoc.createTextNode(""))
                nvt.appendChild(tags)

                certs = self.__xmlDoc.createElement("certs")
                certs.appendChild(self.__xmlDoc.createTextNode(""))
                nvt.appendChild(certs)

                xref = self.__xmlDoc.createElement("xref")
                xref.appendChild(self.__xmlDoc.createTextNode("NOXREF"))
                nvt.appendChild(xref)

                result.appendChild(nvt)

                threat = self.__xmlDoc.createElement("threat")
                threat.appendChild(self.__xmlDoc.createTextNode(str(flaw["level"])))
                result.appendChild(threat)

                description = self.__xmlDoc.createElement("description")
                description.appendChild(self.__xmlDoc.createCDATASection(flaw["info"]))
                result.appendChild(description)

                original_threat = self.__xmlDoc.createElement("original_threat")
                original_threat.appendChild(self.__xmlDoc.createTextNode(str(flaw["level"])))
                result.appendChild(original_threat)

                results.appendChild(result)

        report_infos.appendChild(results)
        report.appendChild(report_infos)

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
        xmlGen = OpenVASReportGenerator()
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
