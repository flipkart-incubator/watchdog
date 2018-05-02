#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2009-2013 Nicolas Surribas
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
import os
from xml.parsers import expat
from xml.dom.minidom import Document
from urllib import quote, unquote
from wapitiCore.net import HTTP


class CrawlerPersister(object):
    """
    This class makes the persistence tasks for persisting the crawler parameters
    in other to can continue the process in the future.
    """

    CRAWLER_DATA_DIR_NAME = "scans"
    HOME_DIR = os.getenv('HOME') or os.getenv('USERPROFILE')
    BASE_DIR = os.path.join(HOME_DIR, ".wapiti")
    CRAWLER_DATA_DIR = os.path.join(BASE_DIR, CRAWLER_DATA_DIR_NAME)

    ROOT_URL = "rootURL"
    TO_BROWSE = "toBrowse"
    BROWSED = "browsed"
    RESOURCE = "resouce"
    METHOD = "method"
    PATH = "path"
    INPUT = "input"
    INPUT_NAME = "name"
    INPUT_VALUE = "value"
    HEADERS = "headers"
    HEADER = "header"
    HEADER_NAME = "name"
    HEADER_VALUE = "value"
    ENCODING = "encoding"
    REFERER = "referer"
    GET_PARAMS = "get_params"
    POST_PARAMS = "post_params"
    FILE_PARAMS = "file_params"

    # toBrowse can contain GET and POST resources
    toBrowse = []
    # browsed contains only GET resources
    browsed = []
    # forms contains only POST resources
    forms = []
    uploads = []
    headers = {}
    rootURL = ""

    tag = ""
    array = None

    method = ""
    path = ""
    encoding = ""
    referer = ""
    get_params = []
    post_params = []
    file_params = []

    def __init__(self):
        pass

    def isDataForUrl(self, fileName):
        return os.path.exists(fileName)

    def saveXML(self, fileName):
        """
        Exports the crawler parameters to an XML file.
        @param fileName The file where is loaded the crawler data
        """
        xml = Document()
        root = xml.createElement("root")
        xml.appendChild(root)

        rootUrlEl = xml.createElement(self.ROOT_URL)
        rootUrlEl.appendChild(xml.createTextNode(self.rootURL.url))
        root.appendChild(rootUrlEl)

        # 1 - URLs and FORMs not yet browsed
        # we don't know several informations yet like the response headers
        toBrowseEl = xml.createElement(self.TO_BROWSE)
        for http_resource in self.toBrowse:
            # <resource method="" path="" encoding ="">
            resEl = xml.createElement(self.RESOURCE)
            resEl.setAttribute(self.METHOD, http_resource.method)
            resEl.setAttribute(self.PATH, http_resource.path)
            resEl.setAttribute(self.ENCODING, http_resource.encoding)
            #   <referer>
            refererEl = xml.createElement(self.REFERER)
            refererEl.appendChild(xml.createTextNode(http_resource.referer))
            resEl.appendChild(refererEl)
            #   <get_params>
            getParamsEl = xml.createElement(self.GET_PARAMS)
            for k, v in http_resource.get_params:
                inputEl = xml.createElement(self.INPUT)
                inputEl.setAttribute(self.INPUT_NAME, quote(k))
                if v is not None:
                    inputEl.setAttribute(self.INPUT_VALUE, quote(v))
                getParamsEl.appendChild(inputEl)
            resEl.appendChild(getParamsEl)

            #   <post_params>
            postParamsEl = xml.createElement(self.POST_PARAMS)
            for k, v in http_resource.post_params:
                inputEl = xml.createElement(self.INPUT)
                inputEl.setAttribute(self.INPUT_NAME, quote(k))
                inputEl.setAttribute(self.INPUT_VALUE, quote(v))
                postParamsEl.appendChild(inputEl)
            resEl.appendChild(postParamsEl)

            #   <file_params>
            fileParamsEl = xml.createElement(self.FILE_PARAMS)
            for k, v in http_resource.file_params:
                inputEl = xml.createElement(self.INPUT)
                inputEl.setAttribute(self.INPUT_NAME, quote(k))
                inputEl.setAttribute(self.INPUT_VALUE, quote(v))
                fileParamsEl.appendChild(inputEl)
            resEl.appendChild(fileParamsEl)

            toBrowseEl.appendChild(resEl)
        root.appendChild(toBrowseEl)

        # 2 - URLs and FORMs already browsed
        browsedEl = xml.createElement(self.BROWSED)
        for http_resource in self.browsed:
            # <resource method="" path="" encoding ="">
            resEl = xml.createElement(self.RESOURCE)
            resEl.setAttribute(self.METHOD, http_resource.method)
            resEl.setAttribute(self.PATH, http_resource.path)
            resEl.setAttribute(self.ENCODING, http_resource.encoding)
            #   <referer>
            refererEl = xml.createElement(self.REFERER)
            refererEl.appendChild(xml.createTextNode(http_resource.referer))
            resEl.appendChild(refererEl)
            #   <get_params>
            getParamsEl = xml.createElement(self.GET_PARAMS)
            for k, v in http_resource.get_params:
                inputEl = xml.createElement(self.INPUT)
                inputEl.setAttribute(self.INPUT_NAME, quote(k))
                if v is not None:
                    inputEl.setAttribute(self.INPUT_VALUE, quote(v))
                getParamsEl.appendChild(inputEl)
            resEl.appendChild(getParamsEl)

            #   <post_params>
            postParamsEl = xml.createElement(self.POST_PARAMS)
            for k, v in http_resource.post_params:
                inputEl = xml.createElement(self.INPUT)
                inputEl.setAttribute(self.INPUT_NAME, quote(k))
                inputEl.setAttribute(self.INPUT_VALUE, quote(v))
                postParamsEl.appendChild(inputEl)
            resEl.appendChild(postParamsEl)

            #   <file_params>
            fileParamsEl = xml.createElement(self.FILE_PARAMS)
            for k, v in http_resource.file_params:
                inputEl = xml.createElement(self.INPUT)
                inputEl.setAttribute(self.INPUT_NAME, quote(k))
                inputEl.setAttribute(self.INPUT_VALUE, quote(v[0]))
                fileParamsEl.appendChild(inputEl)
            resEl.appendChild(fileParamsEl)

            #   <headers>
            headersEl = xml.createElement(self.HEADERS)
            for k, v in http_resource.headers.items():
                if v is None:
                    v = ""
                headEl = xml.createElement(self.HEADER)
                headEl.setAttribute(self.HEADER_NAME, k)
                headEl.setAttribute(self.HEADER_VALUE, v)
                headersEl.appendChild(headEl)
            resEl.appendChild(headersEl)

            browsedEl.appendChild(resEl)
        root.appendChild(browsedEl)

        f = open(fileName, "w")
        try:
                xml.writexml(f, "    ", "    ", "\n", "UTF-8")
        finally:
                f.close()

    def loadXML(self, fileName):
        """
        Loads the crawler parameters from an XML file.
        @param fileName The file from where is loaded the crawler data
        """
        self._parser = expat.ParserCreate("UTF-8")
        self._parser.StartElementHandler = self.__start_element
        self._parser.EndElementHandler = self.__end_element
        self._parser.CharacterDataHandler = self.__char_data
        self._parser.returns_unicode = False

        f = None
        try:
            f = open(fileName)
            content = f.read()
            self.__feed(content.replace("\n", ""))
        finally:
            if f is not None:
                f.close()

    def __feed(self, data):
        self._parser.Parse(data, 0)

    def __close(self):
        self._parser.Parse("", 1)
        del self._parser

    def __start_element(self, name, attrs):
        if name == self.TO_BROWSE:
            self.array = self.toBrowse

        elif name == self.BROWSED:
            self.array = self.browsed

        elif name == self.RESOURCE:
            self.method = attrs[self.METHOD]
            self.path = attrs[self.PATH]
            self.encoding = attrs[self.ENCODING]
            self.referer = ""
            self.headers = {}
            self.get_params = []
            self.post_params = []
            self.file_params = []

        elif name in [self.GET_PARAMS, self.POST_PARAMS, self.FILE_PARAMS, self.REFERER, self.ROOT_URL]:
            self.tag = name

        elif name == self.HEADER:
            self.headers[attrs[self.HEADER_NAME]] = attrs[self.HEADER_VALUE]

        elif name == self.INPUT:
            param_name = unquote(attrs[self.INPUT_NAME])
            if self.INPUT_VALUE in attrs:
                param_value = unquote(attrs[self.INPUT_VALUE])
            else:
                param_value = None

            if self.tag == self.GET_PARAMS:
                self.get_params.append([param_name, param_value])
            if self.tag == self.POST_PARAMS:
                self.post_params.append([param_name, param_value])
            if self.tag == self.FILE_PARAMS:
                self.file_params.append([param_name, param_value])

    def __end_element(self, name):
        if name == self.RESOURCE:
            http_res = HTTP.HTTPResource(self.path,
                                         method=self.method,
                                         encoding=self.encoding,
                                         referer=self.referer,
                                         get_params=self.get_params,
                                         post_params=self.post_params,
                                         file_params=self.file_params)
            http_res.setHeaders(self.headers)

            if self.array is self.toBrowse:
                self.toBrowse.append(http_res)
            else:
                if self.method == "GET":
                    self.browsed.append(http_res)
                elif self.method == "POST":
                    self.forms.append(http_res)

    def __char_data(self, data):
        if self.tag == self.ROOT_URL:
            self.rootURL = data.strip(" ")
        elif self.tag == self.REFERER:
            self.referer = data.strip(" ")

    def setRootURL(self, rootURL):
        self.rootURL = rootURL

    def getRootURL(self):
        return self.rootURL

    def setToBrose(self, toBrowse):
        self.toBrowse = toBrowse

    def getToBrose(self):
        return self.toBrowse

    def setBrowsed(self, browsed):
        self.browsed = browsed

    def getBrowsed(self):
        return self.browsed

    def setForms(self, forms):
        self.forms = forms

    def getForms(self):
        return self.forms

    def setUploads(self, uploads):
        self.uploads = uploads

    def getUploads(self):
        return self.uploads
