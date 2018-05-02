#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2013 Nicolas Surribas
#
# Original authors :
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
class AuxText(object):
    """Class for reading and writing in text files"""
    def readLines(self, fileName):
        """returns a array"""
        lines = []
        f = None
        try:
            # Reminder : don't try to read payload files as UTF-8, must give str type
            f = open(fileName)
            for line in f:
                cleanLine = line.strip(" \n")
                cleanLine = cleanLine.replace("[TAB]", "\t")
                cleanLine = cleanLine.replace("[LF]", "\n")
                if cleanLine != "":
                    lines.append(cleanLine.replace("\\0", "\0"))
        except IOError, e:
            print(e)
        #finally clause do not work with jyton
        #finally:
            #if f!=None:
                #f.close()
        return lines
#class

if __name__ == "__main__":
    try:
        l = AuxText()
        ll = l.readLines("./config/execPayloads.txt")
        for li in ll:
            print(li)
    except SystemExit:
        pass
