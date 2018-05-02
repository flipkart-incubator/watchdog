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
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, Anomaly
import requests
import os
from wapitiCore.net import HTTP


class mod_file(Attack):
    """
    This class implements a file handling attack
    """

    CONFIG_FILE = "fileHandlingPayloads.txt"

    name = "file"

    # The following table contains tuples of (pattern, description, severity)
    # a severity of 1 is a file disclosure (inclusion, read etc) vulnerability
    # a severity of 0 is just the detection of an error returned by the server
    # Most important patterns must appear at the top of this table.
    warnings_desc = [
            # Vulnerabilities
            ("<title>Google</title>",                 _("Remote inclusion vulnerability"), 1),
            ("root:x:0:0",                            _("Linux local file disclosure vulnerability"), 1),
            ("root:*:0:0",                            _("BSD local file disclosure vulnerability"), 1),
            ("[boot loader]",                         _("Windows local file disclosure vulnerability"), 1),
            ("s:12:\"pear.php.net\";",                _("File disclosure vulnerability in include_path"), 1),
            ("PHP Extension and Application Reposit", _("File disclosure vulnerability in include_path"), 1),
            ("PEAR,&nbsp;the&nbsp;PHP&nbsp;Extensio", _("highlight_file() vulnerability in basedir"), 1),
            ("either use the CLI php executable",     _("include() of file in include_path"), 1),
            # Warnings
            ("java.io.FileNotFoundException:",        "Java include/open", 0),
            ("fread(): supplied argument is not",     "fread()", 0),
            ("fpassthru(): supplied argument is not", "fpassthru()", 0),
            ("for inclusion (include_path=",          "include()", 0),
            ("Failed opening required",               "require()", 0),
            ("Warning: file(",                        "file()", 0),
            ("<b>Warning</b>:  file(",                "file()", 0),
            ("Warning: readfile(",                    "readfile()", 0),
            ("<b>Warning:</b>  readfile(",            "readfile()", 0),
            ("Warning: file_get_contents(",           "file_get_contents()", 0),
            ("<b>Warning</b>:  file_get_contents(",   "file_get_contents()", 0),
            ("Warning: show_source(",                 "show_source()", 0),
            ("<b>Warning:</b>  show_source(",         "show_source()", 0),
            ("Warning: highlight_file(",              "highlight_file()", 0),
            ("<b>Warning:</b>  highlight_file(",      "highlight_file()", 0),
            ("System.IO.FileNotFoundException:",      ".NET File.Open*", 0),
            ("error '800a0046'",                      "VBScript OpenTextFile", 0)
    ]

    def __init__(self, http, xmlRepGenerator):
        Attack.__init__(self, http, xmlRepGenerator)
        self.payloads = self.loadPayloads(os.path.join(self.CONFIG_DIR, self.CONFIG_FILE))

    def __findPatternInResponse(self, data, warn):
        """This method searches patterns in the response from the server"""
        err_msg = ""
        inc = 0
        for pattern, description, level in self.warnings_desc:
            if pattern in data:
                if level == 1:
                    err_msg = description
                    inc = 1
                    break
                else:
                    if warn == 0:
                        err_msg = _("Possible {0} vulnerability").format(description)
                        warn = 1
                        break
        return err_msg, inc, warn

    def attackGET(self, http_res):
        """This method performs the file handling attack with method GET"""
        page = http_res.path
        params_list = http_res.get_params
        resp_headers = http_res.headers
        referer = http_res.referer
        headers = {}
        if referer:
            headers["referer"] = referer

        if not params_list:
            # Do not attack application-type files
            if not "content-type" in resp_headers:
                # Sometimes there's no content-type... so we rely on the document extension
                if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                    return
            elif not "text" in resp_headers["content-type"]:
                return

            timeouted = False
            warn = 0
            inc = 0
            err500 = 0

            for payload in self.payloads:
                if "[VALUE]" in payload or "[DIRVALUE]" in payload or "[FILE_NAME]" in payload:
                    continue
                err = ""
                url = page + "?" + self.HTTP.quote(payload)
                if url not in self.attackedGET:
                    if self.verbose == 2:
                        print(u"+ {0}".format(url))
                    self.attackedGET.append(url)
                    evil_req = HTTP.HTTPResource(url)
                    try:
                        data, code = self.HTTP.send(evil_req, headers=headers).getPageCode()
                    except requests.exceptions.Timeout:
                        # Display a warning about timeout only once for a parameter
                        if timeouted:
                            continue
                        data = ""
                        code = "408"
                        err = ""
                        self.logAnom(category=Anomaly.RES_CONSUMPTION,
                                     level=Anomaly.MEDIUM_LEVEL,
                                     request=evil_req,
                                     info=Anomaly.MSG_QS_TIMEOUT)
                        self.logO(Anomaly.MSG_TIMEOUT, page)
                        self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
                        timeouted = True
                    else:
                        err, inc, warn = self.__findPatternInResponse(data, warn)

                    if err != "":
                        self.logVuln(category=Vulnerability.FILE_HANDLING,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     info=_("{0} via injection in the query string").format(err))
                        self.logR(Vulnerability.MSG_QS_INJECT, err, page)
                        self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)
                        if inc:
                            break
                    else:
                        if code == "500" and err500 == 0:
                            err500 = 1
                            self.logAnom(category=Anomaly.ERROR_500,
                                         level=Anomaly.HIGH_LEVEL,
                                         request=evil_req,
                                         info=Anomaly.MSG_QS_500)
                            self.logO(Anomaly.MSG_500, evil_req.path)
                            self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)

        for i in range(len(params_list)):
            timeouted = False
            warn = 0
            inc = 0
            err500 = 0
            param_name = self.HTTP.quote(params_list[i][0])
            saved_value = params_list[i][1]
            if saved_value is None:
                saved_value = ""
            params_list[i][1] = "__FILE__"
            url = page + "?" + self.HTTP.encode(params_list)

            if url not in self.attackedGET:
                self.attackedGET.append(url)
                for payload in self.payloads:
                    err = ""

                    payload = payload.replace('[VALUE]', saved_value)
                    payload = payload.replace('[DIRVALUE]', saved_value.rsplit('/', 1)[0])
                    payload = payload.replace('[FILE_NAME]', http_res.file_name)

                    params_list[i][1] = self.HTTP.quote(payload)
                    url = page + "?" + self.HTTP.encode(params_list)

                    if self.verbose == 2:
                        print(u"+ {0}".format(url))
                    evil_req = HTTP.HTTPResource(url)
                    try:
                        data, code = self.HTTP.send(evil_req, headers=headers).getPageCode()
                    except requests.exceptions.Timeout:
                        if timeouted:
                            continue
                        data = ""
                        code = "408"
                        err = ""
                        self.logAnom(category=Anomaly.RES_CONSUMPTION,
                                     level=Anomaly.MEDIUM_LEVEL,
                                     request=evil_req,
                                     parameter=param_name,
                                     info=Anomaly.MSG_PARAM_TIMEOUT.format(param_name))
                        self.logO(Anomaly.MSG_TIMEOUT, page)
                        self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
                        timeouted = True
                    else:
                        err, inc, warn = self.__findPatternInResponse(data, warn)
                    if err != "":
                        self.logVuln(category=Vulnerability.FILE_HANDLING,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     parameter=param_name,
                                     info=_("{0} via injection in the parameter {1}").format(err, param_name))
                        self.logR(Vulnerability.MSG_PARAM_INJECT, err, page, param_name)
                        self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)
                        if inc:
                            break
                    else:
                        if code == "500" and err500 == 0:
                            err500 = 1
                            self.logAnom(category=Anomaly.ERROR_500,
                                         level=Anomaly.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=Anomaly.MSG_PARAM_500.format(param_name))
                            self.logO(Anomaly.MSG_500, evil_req.path)
                            self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
            params_list[i][1] = saved_value

    def attackPOST(self, form):
        """This method performs the file handling attack with method POST"""

        # copies
        get_params = form.get_params
        post_params = form.post_params
        file_params = form.file_params
        referer = form.referer

        err = ""
        for params_list in [get_params, post_params, file_params]:
            for i in xrange(len(params_list)):
                timeouted = False
                warn = 0
                inc = 0
                err500 = 0

                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""
                param_name = self.HTTP.quote(params_list[i][0])

                if params_list is file_params:
                    params_list[i][1] = ["_FILE__", params_list[i][1][1]]
                else:
                    params_list[i][1] = "__FILE__"

                attack_pattern = HTTP.HTTPResource(form.path,
                                                   method=form.method,
                                                   get_params=get_params,
                                                   post_params=post_params,
                                                   file_params=file_params)
                if attack_pattern not in self.attackedPOST:
                    self.attackedPOST.append(attack_pattern)
                    for payload in self.payloads:
                        payload = payload.replace('[FILE_NAME]', form.file_name)

                        if params_list is file_params:
                            payload = payload.replace('[VALUE]', saved_value[0])
                            payload = payload.replace('[DIRVALUE]', saved_value[0].rsplit('/', 1)[0])
                            params_list[i][1][0] = payload
                        else:
                            payload = payload.replace('[VALUE]', saved_value)
                            payload = payload.replace('[DIRVALUE]', saved_value.rsplit('/', 1)[0])
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
                            data, code = self.HTTP.send(evil_req).getPageCode()
                        except requests.exceptions.Timeout:
                            if timeouted:
                                continue
                            data = ""
                            code = "408"
                            self.logAnom(category=Anomaly.RES_CONSUMPTION,
                                         level=Anomaly.MEDIUM_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=Anomaly.MSG_PARAM_TIMEOUT.format(param_name))
                            self.logO(Anomaly.MSG_TIMEOUT, evil_req.path)
                            self.logO(Anomaly.MSG_EVIL_REQUEST)
                            self.logC(evil_req.http_repr)
                            print('')
                            timeouted = True
                        else:
                            err, inc, warn = self.__findPatternInResponse(data, warn)
                        if err != "":
                            info_msg = _("{0} via injection in the parameter {1}")
                            self.logVuln(category=Vulnerability.FILE_HANDLING,
                                         level=Vulnerability.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=info_msg.format(err, param_name))
                            self.logR(Vulnerability.MSG_PARAM_INJECT, err, evil_req.url, param_name)
                            self.logR(Vulnerability.MSG_EVIL_REQUEST)
                            self.logC(evil_req.http_repr)
                            print('')
                            if inc:
                                break

                        else:
                            if code == "500" and err500 == 0:
                                err500 = 1
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
