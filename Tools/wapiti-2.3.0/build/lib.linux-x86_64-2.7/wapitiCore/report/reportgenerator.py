#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2013 Nicolas Surribas
#
# Original authors :
# Alberto Pastor
# David del Pozo
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
class ReportGenerator(object):
    def generateReport(self, fileName):
        pass

    def setReportInfo(self, target=None, scope=None, date_string="", version=""):
        pass

    # Vulnerabilities
    def addVulnerabilityType(self, name, description="", solution="", references={}):
        pass

    def logVulnerability(self, category=None, level=0, request=None, parameter="", info=""):
        pass

    # Anomalies
    def addAnomalyType(self, name, description="", solution="", references={}):
        pass

    def logAnomaly(self, category=None, level=0, request=None, parameter="", info=""):
        pass
