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


class mod_exec(Attack):
    """
    This class implements a command execution attack
    """

    CONFIG_FILE = "execPayloads.txt"

    name = "exec"

    def __init__(self, http, xmlRepGenerator):
        Attack.__init__(self, http, xmlRepGenerator)
        self.payloads = self.loadPayloads(os.path.join(self.CONFIG_DIR, self.CONFIG_FILE))

    def __findPatternInResponse(self, data, warned):
        err = ""
        cmd = 0
        if "eval()'d code</b> on line <b>" in data and not warned:
            err = ("Warning eval()")
            warned = 1
        if "PATH=" in data and "PWD=" in data:
            err = _("Command execution")
            cmd = 1
        if "w4p1t1_eval" in data:
            err = _("PHP evaluation")
            cmd = 1
        if "Cannot execute a blank command in" in data and not warned:
            err = _("Warning exec")
            warned = 1
        if "sh: command substitution:" in data and not warned:
            err = _("Warning exec")
            warned = 1
        if "Fatal error</b>:  preg_replace" in data and not warned:
            err = _("preg_replace injection")
            warned = 1
        if "Warning: usort()" in data and not warned:
            err = _("Warning usort()")
            warned = 1
        if "Warning: preg_replace():" in data and not warned:
            err = _("preg_replace injection")
            warned = 1
        if "Warning: assert():" in data and not warned:
            err = _("Warning assert")
            warned = 1
        if "Failure evaluating code:" in data and not warned:
            err = _("Evalutation warning")
            warned = 1
        return err, cmd, warned

    def attackGET(self, http_res):
        """This method performs the command execution with method GET"""

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
            warned = 0
            cmd = 0
            err500 = 0

            for payload in self.payloads:
                if "[VALUE]" in payload:
                    continue

                err = ""
                url = page + "?" + self.HTTP.quote(payload)

                if url not in self.attackedGET:
                    evil_req = HTTP.HTTPResource(url)
                    if self.verbose == 2:
                        print(u"+ {0}".format(url))
                    self.attackedGET.append(url)
                    try:
                        data, code = self.HTTP.send(evil_req, headers=headers).getPageCode()
                    except requests.exceptions.Timeout:
                        if timeouted:
                            continue
                        data = ""
                        code = "408"
                        err = ""
                        self.logO(Anomaly.MSG_TIMEOUT, page)
                        self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
                        self.logAnom(category=Anomaly.RES_CONSUMPTION,
                                     level=Anomaly.MEDIUM_LEVEL,
                                     request=evil_req,
                                     info=Anomaly.MSG_QS_TIMEOUT)
                        timeouted = True
                    else:
                        err, cmd, warned = self.__findPatternInResponse(data, warned)
                    if err != "":
                        self.logVuln(category=Vulnerability.EXEC,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     info=Vulnerability.MSG_QS_INJECT.format(err, page))
                        self.logR(Vulnerability.MSG_QS_INJECT, err, page)
                        self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)
                    else:
                        if code == "500" and err500 == 0:
                            err500 = 1
                            self.logAnom(category=Anomaly.ERROR_500,
                                         level=Anomaly.HIGH_LEVEL,
                                         request=evil_req,
                                         info=Anomaly.MSG_QS_500)
                            self.logO(Anomaly.MSG_500, page)
                            self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
                    if cmd:
                        break

        for i in range(len(params_list)):
            timeouted = False
            warned = 0
            cmd = 0
            err500 = 0

            saved_value = params_list[i][1]
            if saved_value is None:
                saved_value = ""
            params_list[i][1] = "__EXEC__"
            url = page + "?" + self.HTTP.encode(params_list)
            param_name = self.HTTP.quote(params_list[i][0])

            if url not in self.attackedGET:
                self.attackedGET.append(url)

                for payload in self.payloads:
                    err = ""
                    payload = payload.replace("[VALUE]", saved_value)
                    params_list[i][1] = self.HTTP.quote(payload)
                    evil_req = HTTP.HTTPResource(page + "?" + self.HTTP.encode(params_list))

                    if self.verbose == 2:
                        print(u"+ {0}".format(evil_req.url))

                    try:
                        data, code = self.HTTP.send(evil_req, headers=headers).getPageCode()
                    except requests.exceptions.Timeout:
                        if timeouted:
                            continue
                        data = ""
                        code = "408"
                        err = ""
                        self.logO(Anomaly.MSG_TIMEOUT, page)
                        self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
                        self.logAnom(category=Anomaly.RES_CONSUMPTION,
                                     level=Anomaly.MEDIUM_LEVEL,
                                     request=evil_req,
                                     parameter=param_name,
                                     info=Anomaly.MSG_PARAM_TIMEOUT.format(param_name))
                        timeouted = True
                    else:
                        err, cmd, warned = self.__findPatternInResponse(data, warned)

                    if err != "":
                        self.logVuln(category=Vulnerability.EXEC,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     parameter=param_name,
                                     info=_("{0} via injection in the parameter {1}").format(err, param_name))
                        self.logR(Vulnerability.MSG_PARAM_INJECT,
                                  err,
                                  page,
                                  param_name)
                        self.logR(Vulnerability.MSG_EVIL_URL, evil_req.url)

                        if cmd:
                            # Successful command execution, go to the next field
                            break
                    else:
                        if code == "500" and err500 == 0:
                            err500 = 1
                            self.logAnom(category=Anomaly.ERROR_500,
                                         level=Anomaly.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=Anomaly.MSG_PARAM_500.format(param_name))
                            self.logO(Anomaly.MSG_500, page)
                            self.logO(Anomaly.MSG_EVIL_URL, evil_req.url)
            params_list[i][1] = saved_value

    def attackPOST(self, form):
        """This method performs the command execution with method POST"""

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
                timeouted = False
                warned = 0
                cmd = 0
                err500 = 0
                param_name = self.HTTP.quote(params_list[i][0])

                if params_list is file_params:
                    params_list[i][1] = ["_EXEC__", params_list[i][1][1]]
                else:
                    params_list[i][1] = "__EXEC__"

                attack_pattern = HTTP.HTTPResource(form.path,
                                                   method=form.method,
                                                   get_params=get_params,
                                                   post_params=post_params,
                                                   file_params=file_params)
                if attack_pattern not in self.attackedPOST:
                    self.attackedPOST.append(attack_pattern)
                    for payload in self.payloads:
                        # no quoting: send() will do it for us
                        if params_list is file_params:
                            payload = payload.replace("[VALUE]", saved_value[0])
                            params_list[i][1][0] = payload
                        else:
                            payload = payload.replace("[VALUE]", saved_value)
                            params_list[i][1] = payload

                        evil_req = HTTP.HTTPResource(form.path,
                                                     method=form.method,
                                                     get_params=get_params,
                                                     post_params=post_params,
                                                     file_params=file_params,
                                                     referer=referer)
                        if self.verbose == 2:
                            print(u"+ {0}".format(evil_req))
                        err = ""
                        try:
                            data, code = self.HTTP.send(evil_req).getPageCode()
                        except requests.exceptions.Timeout:
                            if timeouted:
                                continue
                            data = ""
                            code = "408"
                            self.logO(Anomaly.MSG_TIMEOUT, evil_req.url)
                            self.logO(Anomaly.MSG_EVIL_REQUEST)
                            self.logC(evil_req.http_repr)
                            print('')
                            self.logAnom(category=Anomaly.RES_CONSUMPTION,
                                         level=Anomaly.MEDIUM_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=Anomaly.MSG_PARAM_TIMEOUT.format(param_name))
                            timeouted = True
                        else:
                            err, cmd, warned = self.__findPatternInResponse(data, warned)

                        if err != "":
                            self.logVuln(category=Vulnerability.EXEC,
                                         level=Vulnerability.HIGH_LEVEL,
                                         request=evil_req,
                                         parameter=param_name,
                                         info=_("{0} via injection in the parameter {1}").format(err, param_name))
                            self.logR(Vulnerability.MSG_PARAM_INJECT, err, evil_req.url, param_name)
                            self.logR(Vulnerability.MSG_EVIL_REQUEST)
                            self.logC(evil_req.http_repr)
                            print('')

                            if cmd:
                                # Successful command execution, go to the next field
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
                                self.logO(Vulnerability.MSG_EVIL_REQUEST)
                                self.logC(evil_req.http_repr)
                                print('')
                params_list[i][1] = saved_value
