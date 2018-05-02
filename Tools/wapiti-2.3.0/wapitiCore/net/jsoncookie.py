#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2012-2013 Nicolas Surribas
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
import json
import cookielib
import requests


class jsoncookie(object):

    cookiedict = None
    fd = None

    # return a dictionary on success, None on failure
    def open(self, filename):
        if not filename:
            return None
        try:
            self.fd = open(filename, "r+")
            self.cookiedict = json.load(self.fd)
        except IOError:
            self.fd = open(filename, "w+")
            self.cookiedict = {}
        return self.cookiedict

    def addcookies(self, cookies):
        if not isinstance(cookies, requests.cookies.RequestsCookieJar):
            return False
        for domain, pathdict in cookies._cookies.items():
            dotdomain = domain if domain[0] == '.' else '.' + domain
            if dotdomain not in self.cookiedict.keys():
                self.cookiedict[dotdomain] = {}
            for path, keydict in pathdict.items():
                if path not in self.cookiedict[dotdomain].keys():
                    self.cookiedict[dotdomain][path] = {}
                for key, cookieobj in keydict.items():
                    if isinstance(cookieobj, cookielib.Cookie):
                        print cookieobj
                        cookie_attrs = {}
                        cookie_attrs["value"] = cookieobj.value
                        cookie_attrs["expires"] = cookieobj.expires
                        cookie_attrs["secure"] = cookieobj.secure
                        cookie_attrs["port"] = cookieobj.port
                        cookie_attrs["version"] = cookieobj.version
                        self.cookiedict[dotdomain][path][key] = cookie_attrs

    def cookiejar(self, domain):
        if not domain:
            return None

        dotdomain = domain if domain[0] == '.' else '.' + domain
        exploded = dotdomain.split(".")
        parent_domains = [".%s" % (".".join(exploded[x:])) for x in range(1, len(exploded) - 1)]
        matching_domains = [d for d in parent_domains if d in self.cookiedict]
        if not matching_domains:
            return None

        cj = cookielib.CookieJar()
        for d in matching_domains:
            for path in self.cookiedict[d]:
                for cookie_name, cookie_attrs in self.cookiedict[d][path].items():
                    ck = cookielib.Cookie(version=cookie_attrs["version"],
                                          name=cookie_name,
                                          value=cookie_attrs["value"],
                                          port=None,
                                          port_specified=False,
                                          domain=d,
                                          domain_specified=True,
                                          domain_initial_dot=False,
                                          path=path,
                                          path_specified=True,
                                          secure=cookie_attrs["secure"],
                                          expires=cookie_attrs["expires"],
                                          discard=True,
                                          comment=None,
                                          comment_url=None,
                                          rest={'HttpOnly': None},
                                          rfc2109=False)

                    if cookie_attrs["port"]:
                        ck.port = cookie_attrs["port"]
                        ck.port_specified = True

                    cj.set_cookie(ck)
        return cj

    def delete(self, domain, path=None, key=None):
        if not domain:
            return False
        if domain not in self.cookiedict.keys():
            return False

        if not path:
            # delete whole domain data
            self.cookiedict.pop(domain)
            return True

        # path asked for deletion... but does not exist
        if path not in self.cookiedict[domain].keys():
            return False

        if not key:
            # remove every data on the specified domain for the matching path
            self.cookiedict[domain].pop(path)
            return True

        if key in self.cookiedict[domain][path].keys():
            self.cookiedict[domain][path].pop(key)
            return True
        return False

    def dump(self):
        if not self.fd:
            return False
        self.fd.seek(0)
        self.fd.truncate()
        json.dump(self.cookiedict, self.fd, indent=2)
        return True

    def close(self):
        self.fd.close()
