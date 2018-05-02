#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2013 Nicolas Surribas
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
from wapitiCore.report.reportgenerator import ReportGenerator
import codecs

NB_COLUMNS = 80

# TODO: should use more the python format mini-language
# http://docs.python.org/2/library/string.html#format-specification-mini-language


def center(s):
    if len(s) >= NB_COLUMNS:
        return s
    return s.rjust(len(s) + int((NB_COLUMNS - len(s)) / 2.0))


def title(s):
    return u"{0}\n{1}\n".format(s, "-" * len(s.strip()))

separator = ("*" * NB_COLUMNS) + "\n"


class TXTReportGenerator(ReportGenerator):
    """
    This class generates a Wapiti report in TXT format.
    """

    __flawTypes = {}
    __vulns = {}
    __anomalies = {}
    __infos = {}

    def __init__(self):
        pass

    def setReportInfo(self, target, scope=None, date_string="", version=""):
        self.__infos["target"] = target
        self.__infos["date"] = date_string
        self.__infos["version"] = version
        if scope:
            self.__infos["scope"] = scope

    def generateReport(self, fileName):
        """
        Create a TXT file encoded as UTF-8 with a report of the vulnerabilities which have been logged with
        the methods logVulnerability and logAnomaly.
        """
        f = codecs.open(fileName, mode="w", encoding="UTF-8")
        try:
            f.write(separator)
            f.write(center("{0} - wapiti.sourceforge.net\n".format(self.__infos["version"])))
            f.write(center(_("Report for {0}\n").format(self.__infos["target"])))
            f.write(center(_("Date of the scan : {0}\n").format(self.__infos["date"])))
            if "scope" in self.__infos:
                f.write(center(_("Scope of the scan : {0}\n").format(self.__infos["scope"])))
            f.write(separator)

            f.write(title(_("Summary of vulnerabilities :")))
            for name in self.__vulns:
                if self.__vulns[name]:
                    f.write(_("{0} : {1:>3}\n").format(name, len(self.__vulns[name])).rjust(NB_COLUMNS))
            f.write(separator)

            for name in self.__vulns:
                if self.__vulns[name]:
                    f.write(title(name))
                    for vuln in self.__vulns[name]:
                        f.write(vuln["info"])
                        f.write("\n")
                        #f.write("Involved parameter : {0}\n".format(vuln["parameter"]))
                        f.write(_("Evil request:\n"))
                        f.write(vuln["request"].http_repr)
                        f.write("\n")
                        f.write(_("cURL command PoC : \"{0}\"").format(vuln["request"].curl_repr))
                        f.write("\n\n")
                        f.write(center("*   *   *\n\n"))
                    f.write(separator)

            f.write("\n")
            f.write(center(_("Anomalies found:")))
            f.write("\n\n")
            for name in self.__anomalies:
                if self.__anomalies[name]:
                    f.write(title(name))
                    for anom in self.__anomalies[name]:
                        f.write(anom["info"])
                        f.write("\n")
                        f.write(_("Evil request:\n"))
                        f.write(anom["request"].http_repr)
                        f.write("\n\n")
                        f.write(center("*   *   *\n\n"))
                    f.write(separator)

        finally:
            f.close()

    # Vulnerabilities
    def addVulnerabilityType(self, name,
                             description="",
                             solution="",
                             references={}):
        """
        This method adds a vulnerability type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        logVulnerability(category,level,url,parameter,info) is invoked
        and if there is no vulnerabilty of a type, this type will not be presented
        in the report
        """

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

        if category not in self.__vulns:
            self.__vulns[category] = []
        self.__vulns[category].append({"level": level,
                                       "request": request,
                                       "parameter": parameter,
                                       "info": info})

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

        anom_dict = {"request": request,
                     "info": info,
                     "level": level,
                     "parameter": parameter,
                     }
        if category not in self.__anomalies:
            self.__anomalies[category] = []
        self.__anomalies[category].append(anom_dict)
