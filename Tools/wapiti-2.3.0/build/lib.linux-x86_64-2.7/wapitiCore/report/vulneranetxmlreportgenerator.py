#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2013 Nicolas Surribas
#
# Original authors :
# David del Pozo
# Alberto Pastor
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
import datetime


def isPeerAddrPort(p):
    """Is p a (str,int) tuple? I.E. an (ip_address,port)"""
    if type(p) == tuple and len(p) == 2:
        return type(p[0]) == str and type(p[1]) == int
    else:
        return False


class VulneraNetXMLReportGenerator(ReportGenerator):
    """
    This class generates a report with the method printToFile(fileName) which contains
    the information of all the vulnerabilities notified to this object through the
    method logVulnerability(category,level,url,parameter,info).
    The format of the file is XML and it has the following structure:
    <report type="security">
        <generatedBy id="Wapiti 2.3.0"/>
            <bugTypeList>
                <bugType name="SQL Injection">
                    <bugList/>

    <report>
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
    __vulnerabilityTypeList = None
    __ts = None

    def __init__(self):
        self.__ts = datetime.datetime.now()
        self.__xmlDoc = Document()

    def setReportInfo(self, target, scope=None, date_string="", version=""):
        report = self.__xmlDoc.createElement("Report")

        report.setAttribute("generatedBy", version)
        report.setAttribute("generationDate", self.__ts.isoformat())
        self.__vulnerabilityTypeList = self.__xmlDoc.createElement("VulnerabilityTypeList")
        report.appendChild(self.__vulnerabilityTypeList)

        self.__xmlDoc.appendChild(report)

    def __addToVulnerabilityTypeList(self, vulnerabilityType):
        self.__vulnerabilityTypeList.appendChild(vulnerabilityType)

    def addVulnerabilityType(self, name, description="", solution="", references={}):
        """
        This method adds a vulnerability type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        logVulnerability(category,level,url,parameter,info) is invoked
        and if there is no vulnerabilty of a type, this type will not be presented
        in the report
        """
        vulnerabilityType = self.__xmlDoc.createElement("VulnerabilityType")
        vulnerabilityType.appendChild(self.__xmlDoc.createElement("VulnerabilityList"))

        vulTitleNode = self.__xmlDoc.createElement("Title")
        vulTitleNode.appendChild(self.__xmlDoc.createTextNode(name))
        vulnerabilityType.appendChild(vulTitleNode)

        self.__addToVulnerabilityTypeList(vulnerabilityType)
        if description != "":
            descriptionNode = self.__xmlDoc.createElement("Description")
            descriptionNode.appendChild(self.__xmlDoc.createCDATASection(description))
            vulnerabilityType.appendChild(descriptionNode)
        if solution != "":
            solutionNode = self.__xmlDoc.createElement("Solution")
            solutionNode.appendChild(self.__xmlDoc.createCDATASection(solution))
            vulnerabilityType.appendChild(solutionNode)
        if references != "":
            referencesNode = self.__xmlDoc.createElement("References")
            for ref in references:
                referenceNode = self.__xmlDoc.createElement("Reference")
                nameNode = self.__xmlDoc.createElement("name")
                urlNode = self.__xmlDoc.createElement("url")
                nameNode.appendChild(self.__xmlDoc.createTextNode(ref))
                urlNode.appendChild(self.__xmlDoc.createTextNode(references[ref]))
                referenceNode.appendChild(nameNode)
                referenceNode.appendChild(urlNode)
                referencesNode.appendChild(referenceNode)
            vulnerabilityType.appendChild(referencesNode)
        return vulnerabilityType

    def __addToVulnerabilityList(self, category, vulnerability):
        vulnerabilityType = None
        for node in self.__vulnerabilityTypeList.childNodes:
            titleNode = node.getElementsByTagName("Title")
            if (titleNode.length >= 1 and
                titleNode[0].childNodes.length == 1 and
                    titleNode[0].childNodes[0].wholeText == category):
                vulnerabilityType = node
                break
        if vulnerabilityType is None:
            vulnerabilityType = self.addVulnerabilityType(category)
        vulnerabilityType.childNodes[0].appendChild(vulnerability)

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

        peer = None
        ts = ""

        vulnerability = self.__xmlDoc.createElement("Vulnerability")

        stLevel = None
        if level == 1:
            stLevel = "Low"
        elif level == 2:
            stLevel = "Moderate"
        else:
            stLevel = "Important"

        levelNode = self.__xmlDoc.createElement("Severity")
        levelNode.appendChild(self.__xmlDoc.createTextNode(stLevel))
        vulnerability.appendChild(levelNode)

        tsNode = self.__xmlDoc.createElement("DetectionDate")
        #tsNode.appendChild(self.__xmlDoc.createTextNode(ts.isoformat()))
        vulnerability.appendChild(tsNode)

        ##
        urlDetailNode = self.__xmlDoc.createElement("URLDetail")
        vulnerability.appendChild(urlDetailNode)

        urlNode = self.__xmlDoc.createElement("URL")
        urlNode.appendChild(self.__xmlDoc.createTextNode(request.url))
        urlDetailNode.appendChild(urlNode)

        if peer is not None:
            peerNode = self.__xmlDoc.createElement("Peer")
            if isPeerAddrPort(peer):
                addrNode = self.__xmlDoc.createElement("Addr")
                addrNode.appendChild(self.__xmlDoc.createTextNode(peer[0]))
                peerNode.appendChild(addrNode)

                portNode = self.__xmlDoc.createElement("Port")
                portNode.appendChild(self.__xmlDoc.createTextNode(str(peer[1])))
                peerNode.appendChild(portNode)
            else:
                addrNode = self.__xmlDoc.createElement("Addr")
                addrNode.appendChild(self.__xmlDoc.createTextNode(str(peer)))
                peerNode.appendChild(addrNode)
            urlDetailNode.appendChild(peerNode)

        parameterNode = self.__xmlDoc.createElement("Parameter")
        parameterNode.appendChild(self.__xmlDoc.createTextNode(parameter))
        urlDetailNode.appendChild(parameterNode)

        ##

        infoNode = self.__xmlDoc.createElement("Info")
        info = info.replace("\n", "<br />")
        infoNode.appendChild(self.__xmlDoc.createTextNode(info))
        urlDetailNode.appendChild(infoNode)

        self.__addToVulnerabilityList(category, vulnerability)

    def generateReport(self, fileName):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with
        the method logVulnerability(category,level,url,parameter,info)
        """
        f = open(fileName, "w")
        try:
            f.write(self.__xmlDoc.toxml(encoding="UTF-8"))
        finally:
            f.close()

if __name__ == "__main__":
    SQL_INJECTION = "Sql Injection"
    FILE_HANDLING = "File Handling"
    XSS = "Cross Site Scripting"
    CRLF = "CRLF"
    EXEC = "Commands execution"

    try:
        xmlGen = VulneraNetXMLReportGenerator()
        xmlGen.addVulnerabilityType(SQL_INJECTION, "desc", "recomm")
        xmlGen.addVulnerabilityType(FILE_HANDLING, "desc", "recomm")
        xmlGen.addVulnerabilityType(XSS,           "desc", "recomm")
        xmlGen.addVulnerabilityType(CRLF,          "desc", "recomm")
        xmlGen.addVulnerabilityType(EXEC,          "desc", "recomm")
        xmlGen.logVulnerability(SQL_INJECTION, "1", "url1", "parameter1", "info1")
        xmlGen.logVulnerability(SQL_INJECTION, "2", "url2", "parameter2", "info2")
        xmlGen.logVulnerability(SQL_INJECTION, "2", "url3", "parameter3", "info3")
        xmlGen.logVulnerability(SQL_INJECTION, "3", "url4", "parameter4", "info4")
        xmlGen.logVulnerability(XSS, "3", "url5", "parameter5", "info5")
        xmlGen.logVulnerability(XSS, "3", "url6", "parameter6", "info6")
        xmlGen.logVulnerability(XSS, "2", "url7", "parameter7", "info7")
        xmlGen.logVulnerability(XSS, "1", "url8", "parameter8", "info8")
        xmlGen.logVulnerability(EXEC, "2", "url9", "parameter9", "info9")
        xmlGen.generateReport("sampleReport.xml")
    except SystemExit:
        pass
