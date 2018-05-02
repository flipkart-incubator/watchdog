#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2009-2013 Nicolas Surribas
#
# Original authors :
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
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
from wapitiCore.language.vulnerability import Vulnerability
import socket
import os
from wapitiCore.net import HTTP


class mod_backup(Attack):
    """
    This class implements a "backup attack"
    """

    payloads = []
    CONFIG_FILE = "backupPayloads.txt"

    name = "backup"

    doGET = False
    doPOST = False

    def __init__(self, http, xmlRepGenerator):
        Attack.__init__(self, http, xmlRepGenerator)
        self.payloads = self.loadPayloads(os.path.join(self.CONFIG_DIR, self.CONFIG_FILE))

    def __returnErrorByCode(self, code):
        err = ""
        code = int(code)
        if code == 404:
            err = "Not found"

        if 100 <= code < 300:
            err = "ok"

        return err

    def attackGET(self, http_res):
        if http_res.file_name == "":
            return

        page = http_res.path
        headers = http_res.headers

        # Do not attack application-type files
        if not "content-type" in headers:
            # Sometimes there's no content-type... so we rely on the document extension
            if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                return
        elif not "text" in headers["content-type"]:
            return

        for payload in self.payloads:
            payload = payload.replace("[FILE_NAME]", http_res.file_name)
            url = page.replace(http_res.file_name, payload)

            if self.verbose == 2:
                print(u"+ {0}".format(url))

            if url not in self.attackedGET:
                self.attackedGET.append(url)
                try:
                    evil_req = HTTP.HTTPResource(url)

                    resp = self.HTTP.send(evil_req)
                    data, code = resp.getPageCode()
                    err = self.__returnErrorByCode(code)
                    if err == "ok":
                        self.logR(_("Found backup file !"))
                        self.logR(u"    -> {0}".format(evil_req.url))
                        self.logVuln(category=Vulnerability.BACKUP,
                                     level=Vulnerability.HIGH_LEVEL,
                                     request=evil_req,
                                     info=_("Backup file {0} found for {1}").format(url, page))

                except socket.timeout:
                    break
