#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2013 Nicolas Surribas
#
# Original author :
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
class ReportGeneratorInfo(object):
    key = None
    className = None
    classModule = None

    def getKey(self):
        return self.name

    def getClassModule(self):
        return self.classModule

    def getClassName(self):
        return self.className

    def setKey(self, name):
        self.name = name

    def setClassModule(self, classModule):
        self.classModule = classModule

    def setClassName(self, className):
        self.className = className

    def createInstance(self):
        module = __import__(self.getClassModule(), globals(), locals(), ['NoName'], -1)
        repGenClass = getattr(module, self.getClassName())
        return repGenClass()
