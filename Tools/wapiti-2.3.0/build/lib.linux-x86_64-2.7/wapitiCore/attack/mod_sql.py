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
import re
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, Anomaly
import requests
from wapitiCore.net import HTTP


class mod_sql(Attack):
    """
    This class implements an error-based SQL Injection attack
    """

    TIME_TO_SLEEP = 6
    name = "sql"

    def __init__(self, http, xmlRepGenerator):
        Attack.__init__(self, http, xmlRepGenerator)

    def __findPatternInResponse(self, data):
        if "You have an error in your SQL syntax" in data:
            return _("MySQL Injection")
        if "supplied argument is not a valid MySQL" in data:
            return _("MySQL Injection")
        if ("[Microsoft][ODBC Microsoft Access Driver]" in data or
                "Syntax error in string in query expression " in data):
            return _("Access-Based SQL Injection")
        if "[Microsoft][ODBC SQL Server Driver]" in data:
            return _("MSSQL-Based Injection")
        if 'Microsoft OLE DB Provider for ODBC Drivers</font> <font size="2" face="Arial">error' in data:
            return _("MSSQL-Based Injection")
        if "Microsoft OLE DB Provider for ODBC Drivers" in data:
            return _("MSSQL-Based Injection")
        if "java.sql.SQLException: Syntax error or access violation" in data or \
           "java.sql.SQLException: Unexpected end of command" in data:
            return _("Java.SQL Injection")
        if "PostgreSQL query failed: ERROR: parser:" in data:
            return _("PostgreSQL Injection")
        if "XPathException" in data:
            return _("XPath Injection")
        if "Warning: SimpleXMLElement::xpath():" in data:
            return _("XPath Injection")
        if "supplied argument is not a valid ldap" in data or "javax.naming.NameNotFoundException" in data:
            return _("LDAP Injection")
        if "DB2 SQL error:" in data:
            return _("DB2 Injection")
        if "Dynamic SQL Error" in data:
            return _("Interbase Injection")
        if "Sybase message:" in data:
            return _("Sybase Injection")
        if "Unclosed quotation mark after the character string" in data:
            return _(".NET SQL Injection")
        if "error '80040e14'" in data and "Incorrect syntax near" in data:
            return _("MSSQL-Based Injection")

        ora_test = re.search("ORA-[0-9]{4,}", data)
        if ora_test is not None:
            return _("Oracle Injection") + " " + ora_test.group(0)

        return ""

    def setTimeout(self, timeout):
        self.TIME_TO_SLEEP = str(1 + int(timeout))

    def attackGET(self, http_res):
        """This method performs the SQL Injection attack with method GET"""
        page = http_res.path
        params_list = http_res.get_params
        resp_headers = http_res.headers
        referer = http_res.referer
        headers = {}
        if referer:
            headers["referer"] = referer

        # about this payload : http://shiflett.org/blog/2006/jan/addslashes-versus-mysql-real-escape-string
        payload = "\xBF'\"("
        vuln_found = 0

        if not params_list:
            # Do not attack application-type files
            if not "content-type" in resp_headers:
                # Sometimes there's no content-type... so we rely on the document extension
                if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                    return
            elif not "text" in resp_headers["content-type"]:
                return

            err = ""
            payload = self.HTTP.quote(payload)
            url = page + "?" + payload
            if url not in self.attackedGET:
                self.attackedGET.append(url)
                evil_req = HTTP.HTTPResource(url)

                if self.verbose == 2:
                    print(u"+ {0}".format(url))
                try:
                    resp = self.HTTP.send(evil_req, headers=headers)
                    data, code = resp.getPageCode()
                except requests.exceptions.Timeout, timeout:
                    # No timeout report here... launch blind sql detection later
                    data = ""
                    code = "408"
                    err = ""
                    resp = timeout
                else:
                    err = self.__findPatternInResponse(data)
                if err != "":
                    vuln_found += 1
                    self.logVuln(category=Vulnerability.SQL_INJECTION,
                                 level=Vulnerability.HIGH_LEVEL,
                                 request=evil_req,
                                 info=_("{0} via injection in the query string").format(err))
                    self.logR(Vulnerability.MSG_QS_INJECT, err, page)
                    self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)

                    self.vulnerableGET.append(page + "?" + "__SQL__")

                else:
                    if code == "500":
                        self.logAnom(category=Anomaly.ERROR_500,
                                     level=Anomaly.HIGH_LEVEL,
                                     request=evil_req,
                                     info=Anomaly.MSG_QS_500)
                        self.logO(Anomaly.MSG_500, page)
                        self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
        else:
            for i in range(len(params_list)):
                err = ""
                param_name = self.HTTP.quote(params_list[i][0])
                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""
                params_list[i][1] = "__SQL__"
                pattern_url = page + "?" + self.HTTP.encode(params_list)
                if pattern_url not in self.attackedGET:
                    self.attackedGET.append(pattern_url)

                    params_list[i][1] = self.HTTP.quote(payload)
                    url = page + "?" + self.HTTP.encode(params_list)
                    evil_req = HTTP.HTTPResource(url)

                    if self.verbose == 2:
                        print(u"+ {0}".format(evil_req.url))
                    try:
                        resp = self.HTTP.send(evil_req, headers=headers)
                        data, code = resp.getPageCode()
                    except requests.exceptions.Timeout, timeout:
                        # No timeout report here... launch blind sql detection later
                        data = ""
                        code = "408"
                        err = ""
                        resp = timeout
                    else:
                        err = self.__findPatternInResponse(data)
                    if err != "":
                        self.logVuln(category=Vulnerability.SQL_INJECTION,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     parameter=param_name,
                                     info=("{0} via injection in the parameter {1}").format(err, param_name))
                        self.logR(Vulnerability.MSG_PARAM_INJECT,
                                  err,
                                  page,
                                  param_name)
                        self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)
                        self.vulnerableGET.append(pattern_url)

                    elif code == "500":
                            self.logAnom(category=Anomaly.ERROR_500,
                                         level=Anomaly.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=Anomaly.MSG_PARAM_500.format(param_name))
                            self.logO(Anomaly.MSG_500, page)
                            self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
                params_list[i][1] = saved_value

    def attackPOST(self, form):
        """This method performs the SQL Injection attack with method POST"""
        payload = "\xbf'\"("
        filename_payload = "'\"("
        err = ""

        # copies
        get_params = form.get_params
        post_params = form.post_params
        file_params = form.file_params
        referer = form.referer

        for params_list in [get_params, post_params, file_params]:
            for i in xrange(len(params_list)):
                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""

                if params_list is file_params:
                    params_list[i][1] = ["_SQL__", params_list[i][1][1]]
                else:
                    params_list[i][1] = "__SQL__"

                param_name = self.HTTP.quote(params_list[i][0])
                attack_pattern = HTTP.HTTPResource(form.path,
                                                   method=form.method,
                                                   get_params=get_params,
                                                   post_params=post_params,
                                                   file_params=file_params)
                if attack_pattern not in self.attackedPOST:
                    self.attackedPOST.append(attack_pattern)

                    if params_list is file_params:
                        params_list[i][1][0] = filename_payload
                    else:
                        params_list[i][1] = payload

                    evil_req = HTTP.HTTPResource(form.path,
                                                 method=form.method,
                                                 get_params=get_params,
                                                 post_params=post_params,
                                                 file_params=file_params,
                                                 referer=referer)
                    if self.verbose == 2:
                        print(u"+ {0}".format(evil_req))

                    try:
                        resp = self.HTTP.send(evil_req)
                        data, code = resp.getPageCode()
                    except requests.exceptions.Timeout, timeout:
                        # No timeout report here... launch blind sql detection later
                        data = ""
                        code = "408"
                        resp = timeout
                    else:
                        err = self.__findPatternInResponse(data)
                    if err != "":
                        self.logVuln(category=Vulnerability.SQL_INJECTION,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     parameter=param_name,
                                     info=_("{0} via injection in the parameter {1}").format(err, param_name))
                        self.logR(Vulnerability.MSG_PARAM_INJECT,
                                  err,
                                  evil_req.url,
                                  param_name)
                        self.logR(Vulnerability.MSG_EVIL_REQUEST)
                        self.logC(evil_req.http_repr)
                        print('')
                        self.vulnerablePOST.append(attack_pattern)

                    else:
                        if code == "500":
                            self.logAnom(category=Anomaly.ERROR_500,
                                         level=Anomaly.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=Anomaly.MSG_PARAM_500.format(param_name))
                            self.logO(Anomaly.MSG_500, evil_req.url)
                            self.logO(Anomaly.MSG_EVIL_REQUEST)
                            self.logC(evil_req.http_repr)
                            print('')

                params_list[i][1] = saved_value
