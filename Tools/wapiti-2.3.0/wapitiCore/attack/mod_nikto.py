#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2009-2013 Nicolas Surribas
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
import csv
import re
import os
import socket
import random
import BeautifulSoup
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability
from wapitiCore.net import HTTP

# Nikto databases are csv files with the following fields (in order) :
#
# 1 - A unique indenfier (number)
# 2 - The OSVDB reference number of the vulnerability
# 3 - Unknown (not used by Wapiti)
# 4 - The URL to check for. May contain a pattern to replace (eg: @CGIDIRS)
# 5 - The HTTP method to use when requesting the URL
# 6 - The HTTP status code returned when the vulnerability may exist
#     or a string the HTTP response may contain.
# 7 - Another condition for a possible vulnerability (6 OR 7)
# 8 - Another condition (must match for a possible vulnerability)
# 9 - A condition corresponding to an unexploitable webpage
#10 - Another condition just like 9
#11 - A description of the vulnerability with possible BID, CVE or MS references
#12 - A url-form-encoded string (usually for POST requests)
#
# A possible vulnerability is reported in the following condition :
# ((6 or 7) and 8) and not (9 or 10)


class mod_nikto(Attack):
    """
    This class implements a Nikto attack
    """

    nikto_db = []

    name = "nikto"
    CONFIG_FILE = "nikto_db"

    doGET = False
    doPOST = False

    def __init__(self, http, xmlRepGenerator):
        Attack.__init__(self, http, xmlRepGenerator)
        user_config_dir = os.getenv('HOME') or os.getenv('USERPROFILE')
        user_config_dir += "/config"
        if not os.path.isdir(user_config_dir):
            os.makedirs(user_config_dir)
        try:
            fd = open(os.path.join(user_config_dir, self.CONFIG_FILE))
            reader = csv.reader(fd)
            self.nikto_db = [l for l in reader if l != [] and l[0].isdigit()]
            fd.close()
        except IOError:
            try:
                print(_("Problem with local nikto database."))
                print(_("Downloading from the web..."))
                nikto_req = HTTP.HTTPResource("http://cirt.net/nikto/UPDATES/2.1.5/db_tests")
                resp = self.HTTP.send(nikto_req)
                page = resp.getRawPage()

                csv.register_dialect("nikto", quoting=csv.QUOTE_ALL, doublequote=False, escapechar="\\")
                reader = csv.reader(page.split("\n"), "nikto")
                self.nikto_db = [l for l in reader if l != [] and l[0].isdigit()]

                fd = open(os.path.join(user_config_dir, self.CONFIG_FILE), "w")
                writer = csv.writer(fd)
                writer.writerows(self.nikto_db)
                fd.close()
            except socket.timeout:
                print(_("Error downloading Nikto database"))

    def attack(self, urls, forms):
        junk_string = "w" + "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 5000)])
        for l in self.nikto_db:
            match = match_or = match_and = False
            fail = fail_or = False

            osv_id = l[1]
            path = l[3]
            method = l[4]
            vuln_desc = l[10]
            post_data = l[11]

            path = path.replace("@CGIDIRS", "/cgi-bin/")
            path = path.replace("@ADMIN", "/admin/")
            path = path.replace("@NUKE", "/modules/")
            path = path.replace("@PHPMYADMIN", "/phpMyAdmin/")
            path = path.replace("@POSTNUKE", "/postnuke/")
            path = re.sub("JUNK\((\d+)\)", lambda x: junk_string[:int(x.group(1))], path)

            if path[0] == "@":
                continue
            if path[0] != "/":
                path = "/" + path

            url = ""
            try:
                url = "http://" + self.HTTP.server + path
            except UnicodeDecodeError:
                continue

            evil_req = None

            if method == "GET":
                evil_req = HTTP.HTTPResource(url)
            elif method == "POST":
                evil_req = HTTP.HTTPResource(url, post_params=post_data, method=method)
            else:
                evil_req = HTTP.HTTPResource(url, post_params=post_data, method=method)

            if self.verbose == 2:
                try:
                    if method == "GET":
                        print(u"+ {0}".format(evil_req.url))
                    else:
                        print(u"+ {0}".format(evil_req.http_repr))
                except Exception, e:
                    continue

            try:
                resp = self.HTTP.send(evil_req)
            except Exception, e:
                # requests bug
                print(e)
                continue

            page, code = resp.getPageCode()
            encoding = BeautifulSoup.BeautifulSoup(page).originalEncoding
            if encoding:
                page = unicode(page, encoding, "ignore")
            raw = " ".join([x + ": " + y for x, y in resp.getHeaders().items()])
            raw += page

            # First condition (match)
            if len(l[5]) == 3 and l[5].isdigit():
                if code == int(l[5]):
                    match = True
            else:
                if l[5] in raw:
                    match = True

            # Second condition (or)
            if l[6] != "":
                if len(l[6]) == 3 and l[6].isdigit():
                    if code == int(l[6]):
                        match_or = True
                else:
                    if l[6] in raw:
                        match_or = True

            # Third condition (and)
            if l[7] != "":
                if len(l[7]) == 3 and l[7].isdigit():
                    if code == int(l[7]):
                        match_and = True
                else:
                    if l[7] in raw:
                        match_and = True
            else:
                match_and = True

            # Fourth condition (fail)
            if l[8] != "":
                if len(l[8]) == 3 and l[8].isdigit():
                    if code == int(l[8]):
                        fail = True
                else:
                    if l[8] in raw:
                        fail = True

            # Fifth condition (or)
            if l[9] != "":
                if len(l[9]) == 3 and l[9].isdigit():
                    if code == int(l[9]):
                        fail_or = True
                else:
                    if l[9] in raw:
                        fail_or = True

            if ((match or match_or) and match_and) and not (fail or fail_or):
                print(url)
                print(vuln_desc)
                refs = []
                if osv_id != "0":
                    refs.append("http://osvdb.org/show/osvdb/" + osv_id)

                # CERT
                m = re.search("(CA\-[0-9]{4}-[0-9]{2})", vuln_desc)
                if m is not None:
                    refs.append("http://www.cert.org/advisories/" + m.group(0) + ".html")

                # SecurityFocus
                m = re.search("BID\-([0-9]{4})", vuln_desc)
                if m is not None:
                    refs.append("http://www.securityfocus.com/bid/" + m.group(1))

                # Mitre.org
                m = re.search("((CVE|CAN)\-[0-9]{4}-[0-9]{4})", vuln_desc)
                if m is not None:
                    refs.append("http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + m.group(0))

                # CERT Incidents
                m = re.search("(IN\-[0-9]{4}\-[0-9]{2})", vuln_desc)
                if m is not None:
                    refs.append("http://www.cert.org/incident_notes/" + m.group(0) + ".html")

                # Microsoft Technet
                m = re.search("(MS[0-9]{2}\-[0-9]{3})", vuln_desc)
                if m is not None:
                    refs.append("http://www.microsoft.com/technet/security/bulletin/" + m.group(0) + ".asp")

                info = vuln_desc
                if refs != []:
                    print(_("References:"))
                    print(u"  {0}".format(u"\n  ".join(refs)))
                    info += "\n" + _("References:") + "\n"
                    info += "\n".join(['<a href="' + x + '">' + x + '</a>' for x in refs])
                print('')

                self.logVuln(category=Vulnerability.NIKTO,
                             level=Vulnerability.HIGH_LEVEL,
                             request=evil_req,
                             info=info)
