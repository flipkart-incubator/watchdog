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
import os
import socket  # for trapping socket.error
from wapitiCore.file.auxtext import AuxText
import requests
import sys

modules = ["mod_crlf", "mod_exec", "mod_file", "mod_sql", "mod_xss",
           "mod_backup", "mod_htaccess", "mod_blindsql",
           "mod_permanentxss", "mod_nikto"]


class Attack(object):
    """
    This class represents an attack, it must be extended
    for any class which implements a new type of attack
    """
    verbose = 0
    color = 0

    name = "attack"

    logVuln = None
    logAnom = None
    HTTP = None
    auxText = None

    doGET = True
    doPOST = True

    # List of modules (strs) that must be launched before the current module
    # Must be defined in the code of the module
    require = []
    # List of modules (objects) that must be launched before the current module
    # Must be left empty in the code
    deps = []

    # List of attack's url already launched in the current module
    attackedGET = []
    attackedPOST = []

    vulnerableGET = []
    vulnerablePOST = []

    CONFIG_DIR = ""
    if hasattr(sys, "frozen"):
        BASE_DIR = os.path.join(os.path.dirname(unicode(sys.executable, sys.getfilesystemencoding())), "data")
    else:
        BASE_DIR = os.path.dirname(sys.modules['wapitiCore'].__file__)
    CONFIG_DIR = os.path.join(BASE_DIR, "config", "attacks")

    # Color codes
    STD = "\033[0;0m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    ORANGE = "\033[0;33m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[0;35m"
    CYAN = "\033[0;36m"
    GB = "\033[0;30m\033[47m"

    allowed = ['php', 'html', 'htm', 'xml', 'xhtml', 'xht', 'xhtm',
               'asp', 'aspx', 'php3', 'php4', 'php5', 'txt', 'shtm',
               'shtml', 'phtm', 'phtml', 'jhtml', 'pl', 'jsp', 'cfm',
               'cfml', 'py']

    # The priority of the module, from 0 (first) to 10 (last). Default is 5
    PRIORITY = 5

    def __init__(self, http, reportGen):
        self.HTTP = http
        self.logVuln = reportGen.logVulnerability
        self.logAnom = reportGen.logAnomaly
        self.auxText = AuxText()
        self.attackedGET = []
        self.attackedPOST = []

    def setVerbose(self, verbose):
        self.verbose = verbose

    def setColor(self):
        self.color = 1

    def loadPayloads(self, fileName):
        """Load the payloads from the specified file"""
        return self.auxText.readLines(fileName)

    def attackGET(self, page, params_list, headers={}):
        return

    def attackPOST(self, form):
        return

    def loadRequire(self, obj=[]):
        self.deps = obj

    def log(self, fmt_string, *args):
        if len(args) == 0:
            print(fmt_string)
        else:
            print(fmt_string.format(*args))
        if self.color:
            sys.stdout.write(self.STD)

    def logR(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.RED)
        self.log(fmt_string, *args)

    def logG(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.GREEN)
        self.log(fmt_string, *args)

    def logY(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.YELLOW)
        self.log(fmt_string, *args)

    def logC(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.CYAN)
        self.log(fmt_string, *args)

    def logW(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.GB)
        self.log(fmt_string, *args)

    def logM(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.MAGENTA)
        self.log(fmt_string, *args)

    def logB(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.BLUE)
        self.log(fmt_string, *args)

    def logO(self, fmt_string, *args):
        if self.color:
            sys.stdout.write(self.ORANGE)
        self.log(fmt_string, *args)

    def attack(self, http_resources, forms):
        if self.doGET is True:
            for http_res in http_resources:
                url = http_res.url

                if self.verbose == 1:
                    self.log(_("+ attackGET {0}"), url)

                try:
                    self.attackGET(http_res)
                except socket.error, se:
                    self.log(_('error: {0} while attacking {1}'), repr(str(se[0])), url)
                except requests.exceptions.Timeout:
                    self.log(_('error: timeout while attacking {0}'), url)
                #except Exception, e:
                #    self.log(_('error: {0} while attacking {1}'), repr(str(e[0])), url)

        if self.doPOST is True:
            for form in forms:
                if self.verbose == 1:
                    self.log(_("+ attackPOST {0} from {1}"), form.url, form.referer)

                try:
                    self.attackPOST(form)
                except socket.error, se:
                    self.log(_('error: {0} while attacking {1}'), repr(str(se[0])), url)
                except requests.exceptions.Timeout:
                    print(_('error: timeout while attacking {0}').format(url))
         #       except Exception, e:
         #           self.log(_('error: {0} while attacking {1}'), repr(str(e[0])), url)
