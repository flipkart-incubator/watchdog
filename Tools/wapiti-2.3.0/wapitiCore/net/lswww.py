#!/usr/bin/env python
# -*- coding: utf-8 -*-
# lswww v2.4.0 - A web spider library
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2006-2013 Nicolas Surribas
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
import sys
import re
import socket
import getopt
import os
import HTMLParser
import urllib
import urlparse
import requests
from htmlentitydefs import name2codepoint as n2cp
from xml.dom import minidom
import BeautifulSoup

from wapitiCore.net import jsoncookie
from wapitiCore.net import HTTP
from wapitiCore.net import swf_parser
from wapitiCore.net import lamejs
from wapitiCore.net.crawlerpersister import CrawlerPersister


class lswww(object):
    """
    lswww explore a website and extract links and forms fields.

    Usage: python lswww.py http://server.com/base/url/ [options]

    Supported options are:
        -s <url>
        --start <url>
            To specify an url to start with

        -x <url>
        --exclude <url>
            To exclude an url from the scan (for example logout scripts)
            You can also use a wildcard (*)
            Exemple : -x "http://server/base/?page=*&module=test"
            or -x http://server/base/admin/* to exclude a directory

        -p <url_proxy>
        --proxy <url_proxy>
            To specify a proxy
            Exemple: -p http://proxy:port/

        -c <cookie_file>
        --cookie <cookie_file>
            To use a cookie

        -a <login%password>
        --auth <login%password>
            Set credentials for HTTP authentication
            Doesn't work with Python 2.4

        -r <parameter_name>
        --remove <parameter_name>
            Remove a parameter from URLs

        -v <level>
        --verbose <level>
            Set verbosity level
            0: only print results
            1: print a dot for each url found (default)
            2: print each url

        -t <timeout>
        --timeout <timeout>
            Set the timeout (in seconds)

        -n <limit>
        --nice <limit>
            Define a limit of urls to read with the same pattern
            Use this option to prevent endless loops
            Must be greater than 0

        -i <file>
        --continue <file>
            This parameter indicates Wapiti to continue with the scan
            from the specified file, this file should contain data
            from a previous scan.
            The file is optional, if it is not specified, Wapiti takes
            the default file from \"scans\" folder.

        -h
        --help
            To print this usage message
    """

    SCOPE_DOMAIN = "domain"
    SCOPE_FOLDER = "folder"
    SCOPE_PAGE = "page"
    SCOPE_DEFAULT = "default"

    root = ""
    server = ""
    tobrowse = []
    out_of_scope_urls = []
    browsed = []
    proxies = {}
    excluded = []
    forms = []
    uploads = []
    allowed = ['php', 'html', 'htm', 'xml', 'xhtml', 'xht', 'xhtm',
               'asp', 'aspx', 'php3', 'php4', 'php5', 'txt', 'shtm',
               'shtml', 'phtm', 'phtml', 'jhtml', 'pl', 'jsp', 'cfm', 'cfml']
    allowed_types = ['text/', 'application/xml']
    verbose = 0
    auth_basic = []
    bad_params = []
    timeout = 6.0
    h = None
    global_headers = {}
    cookiejar = None
    scope = None
    link_encoding = {}

    persister = None

    # 0 means no limits
    nice = 0

    def __init__(self, root, http_engine=None, crawlerFile=None):
        self.h = http_engine
        if root.startswith("-"):
            print(_("First argument must be the root url !"))
            sys.exit(0)
        if not "://" in root:
            root = "http://" + root
        if(self.__checklink(root)):
            print(_("Invalid protocol: {0}").format(root.split("://")[0]))
            sys.exit(0)
        if root[-1] != "/" and not "/" in root.split("://")[1]:
            root += "/"

        server = (root.split("://")[1]).split("/")[0]
        self.root = HTTP.HTTPResource(root)   # Initial URL
        self.server = server  # Domain
        self.scopeURL = root  # Scope of the analysis

        self.tobrowse.append(self.root)
        self.persister = CrawlerPersister()

    def setTimeOut(self, timeout=6.0):
        """Set the timeout in seconds to wait for a page"""
        self.timeout = timeout

    def setProxy(self, proxy=""):
        """Set proxy preferences"""
        url_parts = urlparse.urlparse(proxy)
        protocol = url_parts.scheme
        host = url_parts.netloc
        if protocol in ["http", "https"]:
            if host:
                self.proxies[protocol] = "%s://%s/" % (protocol, host)

    def setNice(self, nice=0):
        """Set the maximum of urls to visit with the same pattern"""
        self.nice = nice

    def setScope(self, scope):
        self.scope = scope
        if scope == self.SCOPE_FOLDER:
            self.scopeURL = "/".join(self.root.url.split("/")[:-1]) + "/"
        elif scope == self.SCOPE_DOMAIN:
            self.scopeURL = self.root.url.split("/")[0] + "//" + self.server

    def addStartURL(self, url):
        if(self.__checklink(url)):
            print(_("Invalid link argument: {0}").format(url))
            sys.exit(0)
        if self.__inzone(url) == 0:
            self.tobrowse.append(HTTP.HTTPResource(url))
        else:
            self.out_of_scope_urls.append(HTTP.HTTPResource(url))

    def addExcludedURL(self, url):
        """Add an url to the list of forbidden urls"""
        self.excluded.append(url)

    def setCookieFile(self, cookie):
        """Set the file to read the cookie from"""
        if os.path.isfile(cookie):
            jc = jsoncookie.jsoncookie()
            jc.open(cookie)
            self.cookiejar = jc.cookiejar(self.server)
            jc.close()

    def setAuthCredentials(self, auth_basic):
        self.auth_basic = auth_basic

    def addBadParam(self, bad_param):
        self.bad_params.append(bad_param)

    def browse(self, web_resource):
        """Extract urls from a webpage and add them to the list of urls
        to browse if they aren't in the exclusion list"""
        url = web_resource.url

        # We don't need destination anchors
        current_full_url = url.split("#")[0]
        # Url without query string
        current = current_full_url.split("?")[0]
        # Get the dirname of the file
        currentdir = "/".join(current.split("/")[:-1]) + "/"

        # Timeout must not be too long to block big documents
        # (for exemple a download script)
        # and not too short to give good results
        socket.setdefaulttimeout(self.timeout)

        headers = {}
        headers["user-agent"] = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
        try:
            resp = self.h.send(web_resource, headers=headers)
        except socket.timeout:
            self.excluded.append(url)
            return False
        except requests.exceptions.Timeout:
            self.excluded.append(url)
            return False
        except socket.error, msg:
            if msg.errno == 111:
                print(_("Connection refused!"))
            self.excluded.append(url)
            return False
        except Exception, e:
            print(_("Exception in lswww.browse: {0}").format(e))
            self.excluded.append(url)
            return False

        info = resp.getHeaders()
        code = resp.getCode()
        info["status_code"] = code

        if not url in self.link_encoding:
            self.link_encoding[url] = ""

        proto = url.split("://")[0]
        if proto == "http" or proto == "https":
            if not isinstance(proto, unicode):
                proto = unicode(proto)
            # Check the content-type first
            # if not info.has_key("content-type"):
                # Sometimes there's no content-type...
                #so we rely on the document extension
            # if (current.split(".")[-1] not in self.allowed)
            #    and current[-1] != "/":
            #    return info
            # elif info["content-type"].find("text") == -1:
            #   return info

        # No files more than 2MB
        if "content-length" in info:
            if int(info["content-length"]) > 2097152:
                return False

        page_encoding = None
        resp_encoding = resp.getEncoding()
        content_type = resp.getHeaders().get('content-type', '')
        mime_type = content_type.split(';')[0].strip()
        swf_links = []
        js_links = []

        # Requests says it found an encoding... the content must be some HTML
        if resp_encoding and any(mime_type.startswith(t) for t in self.allowed_types):
            # But Requests doesn't take a deep look at the webpage,
            # so check it with BeautifulSoup
            page_encoding = BeautifulSoup.BeautifulSoup(resp.getRawPage()).originalEncoding
            if page_encoding and page_encoding.upper() != resp_encoding:
                # Mismatch ! Convert the response text to the encoding detected by BeautifulSoup
                resp.setEncoding(page_encoding)
            data = resp.getPage()
        else:
            # Can't find an encoding... beware of non-html content
            data = resp.getRawPage()
            if "application/x-shockwave-flash" in mime_type or web_resource.file_ext == "swf":
                try:
                    flash_parser = swf_parser.swf_parser(data)
                    swf_links = flash_parser.getLinks()
                except Exception, err_data:
                    swf_links = err_data[1]
                data = ""
            elif "/x-javascript" in mime_type or "/x-js" in mime_type or "/javascript" in mime_type:
                js_links = lamejs.lamejs(data).getLinks()
                data = ""

        # Manage redirections
        if "location" in info:
            redir = self.correctlink(info["location"], current, current_full_url, currentdir, proto, None)
            if redir is not None:
                if self.__inzone(redir) == 0:
                    self.link_encoding[redir] = self.link_encoding[url]
                    redir = HTTP.HTTPResource(redir)
                    # Is the document already visited of forbidden ?
                    if (redir in self.browsed) or (redir in self.tobrowse) or \
                            self.isExcluded(redir):
                        pass
                    else:
                        # No -> Will browse it soon
                        self.tobrowse.append(redir)

        htmlSource = data
        if page_encoding:
            bs = BeautifulSoup.BeautifulSoup(htmlSource)
            # Look for a base tag with an href attribute
            if bs.head:
                baseTags = bs.head.findAll("base")
                for base in baseTags:
                    # BeautifulSoup doesn't work as excepted with the "in" statement, keep this:
                    if base.has_key("href"):
                        # Found a base url, now set it as the current url
                        current = base["href"].split("#")[0]
                        # We don't need destination anchors
                        current = current.split("?")[0]
                        # Get the dirname of the file
                        currentdir = "/".join(current.split("/")[:-1]) + "/"
                        break

        #if page_encoding != None:
        #  htmlSource = unicode(data, page_encoding, "ignore")
        #else:
        #  htmlSource = data

        p = linkParser(url)
        try:
            p.feed(htmlSource)
        except HTMLParser.HTMLParseError:
            htmlSource = BeautifulSoup.BeautifulSoup(htmlSource).prettify()
            if not isinstance(htmlSource, unicode) and page_encoding is not None:
                htmlSource = unicode(htmlSource, page_encoding, "ignore")
            try:
                p.reset()
                p.feed(htmlSource)
            except HTMLParser.HTMLParseError:
                p = linkParser2(url, self.verbose)
                p.feed(htmlSource)

        # Sometimes the page is badcoded but the parser doesn't see the error
        # So if we got no links we can force a correction of the page
        if len(p.liens) == 0:
            if page_encoding is not None:
                try:
                    htmlSource = BeautifulSoup.BeautifulSoup(htmlSource).prettify(page_encoding)
                    p.reset()
                    p.feed(htmlSource)
                except UnicodeEncodeError:
                    # The resource is not a valid webpage (for example an image)
                    htmlSource = ""
                except HTMLParser.HTMLParseError:
                    p = linkParser2(url, self.verbose)
                    p.feed(htmlSource)

        found_links = p.liens + swf_links + js_links
        for lien in found_links:
            if (lien is not None) and (page_encoding is not None) and isinstance(lien, unicode):
                lien = lien.encode(page_encoding, "ignore")
            lien = self.correctlink(lien, current, current_full_url, currentdir, proto, page_encoding)
            if lien is not None:
                if self.__inzone(lien) == 0:
                    # Is the document already visited of forbidden ?
                    lien = HTTP.HTTPResource(lien, encoding=page_encoding, referer=url)
                    if ((lien in self.browsed) or
                        (lien in self.tobrowse) or
                        self.isExcluded(lien) or
                            self.__inzone(lien.url) != 0):
                        pass
                    elif self.nice > 0:
                        if self.__countMatches(lien) >= self.nice:
                            # don't waste time next time we found it
                            self.excluded.append(lien.url)
                            return False
                        else:
                            self.tobrowse.append(lien)
                    else:
                        # No -> Will browse it soon
                        self.tobrowse.append(lien)
                    # Keep the encoding of the current webpage for the future requests to the link
                    # so we can encode the query string parameters just as a browser would do.
                    # Of course websites encoding may be broken :(
                    self.link_encoding[lien] = page_encoding

        for form in p.forms:
            action = self.correctlink(form[0], current, current_full_url, currentdir, proto, page_encoding)
            if action is None:
                action = current
            if self.__inzone(action) != 0:
                continue

            # urlencode the POST parameters here
            params = form[1]
            post_params = []
            files = []
            for kv in params:
                if isinstance(kv[0], unicode):
                    kv[0] = kv[0].encode(page_encoding, "ignore")

                if isinstance(kv[1], list):
                    fname = kv[1][0]
                    if isinstance(fname, unicode):
                        fname = fname.encode(page_encoding, "ignore")
                    files.append([kv[0], [fname, kv[1][1]]])
                else:
                    if isinstance(kv[1], unicode):
                        kv[1] = kv[1].encode(page_encoding, "ignore")
                    post_params.append([kv[0], kv[1]])

            form_rsrc = HTTP.HTTPResource(action,
                                          method="POST",
                                          post_params=post_params,
                                          file_params=files,
                                          encoding=page_encoding,
                                          referer=url)
            if form_rsrc not in self.forms:
                self.forms.append(form_rsrc)
            if not (form_rsrc in self.browsed or form_rsrc in self.tobrowse):
                self.tobrowse.append(form_rsrc)
            if files:
                if form_rsrc not in self.uploads:
                    self.uploads.append(form_rsrc)
        # We automaticaly exclude 404 urls
        if code == "404":
            self.excluded.append(url)
            #return {} # exclude from scan but can be useful for some modules maybe

        return True

    def correctlink(self, lien, current_url, current_full_url, current_directory, protocol, encoding):
        """Transform relatives urls in absolutes ones"""

        if lien is None:
            return current_full_url

        # No destination anchor
        if "#" in lien:
            lien = lien.split("#")[0]

        # No leading or trailing whitespaces
        lien = lien.strip()

        if lien == "":
            return current_full_url

        if lien == "..":
            lien = "../"
        # bad protocols
        llien = lien.lower()
        if (llien.startswith("telnet:") or
            llien.startswith("ftp:") or
            llien.startswith("mailto:") or
            llien.startswith("javascript:") or
            llien.startswith("news:") or
            llien.startswith("file:", 0) or
            llien.startswith("gopher:") or
                llien.startswith("irc:", 0)):
            return None
        # Good protocols or relatives links
        else:
            # full url, nothing to do :)
            if lien.startswith("http://") or lien.startswith("https://"):
                pass
            else:
                # Protocol relative URLs
                if lien.startswith("//"):
                    lien = protocol + ":" + lien
                # root-url related link
                elif lien[0] == '/':
                    lien = "{0}://{1}{2}".format(protocol, self.server, lien)
                else:
                    # same page + query string
                    if lien[0] == '?':
                        lien = current_url + lien
                    # current_url directory related link
                    else:
                        lien = current_directory + lien

            args = ""
            if "?" in lien:
                lien, args = lien.split("?", 1)
                # if args is a unicode string, encode it according to the
                # charset of the webpage (if known)
                if encoding and isinstance(args, unicode):
                    args = args.encode(encoding, "ignore")

                # a hack for auto-generated Apache directory index
                if args in ["C=D;O=A", "C=D;O=D", "C=M;O=A", "C=M;O=D",
                            "C=N;O=A", "C=N;O=D", "C=S;O=A", "C=S;O=D"]:
                    args = ""

                if "&" in args:
                    args = args.split("&")
                    args = [i for i in args if i != "" and "=" in i]
                    for i in self.bad_params:
                        for j in args:
                            if j.startswith(i + "="):
                                args.remove(j)
                    args = "&".join(args)

            # First part of the url (path) must be encoded with UTF-8
            if isinstance(lien, unicode):
                lien = lien.encode("UTF-8", "ignore")
            lien = urllib.quote(lien, safe='/#%[]=:;$&()+,!?*')

            # remove useless slashes repetitions (expect those from the protocol)
            lien = re.sub("([^:])//+", r"\1/", lien)
            if lien[-2:] == "/.":
                lien = lien[:-1]

            # It should be safe to parse now
            parsed = urlparse.urlparse(lien)
            path = parsed.path

            # links going to a parrent directory (..)
            while re.search("/([~:!,;a-zA-Z0-9\.\-+_]+)/\.\./", path) is not None:
                path = re.sub("/([~:!,;a-zA-Z0-9\.\-+_]+)/\.\./", "/", path)
            while re.search("/\./", path) is not None:
                path = re.sub("/\./", "/", path)
            if path == "":
                path = '/'

            # Fix for path going back up the root directory (eg: http://srv/../../dir/)
            path = re.sub(r'^(/?\.\.//*)*', '',  path)
            if not path.startswith('/'):
                path = '/' + path

            lien = "%s://%s%s" % (parsed.scheme, parsed.netloc, path)
            if args != "":
                # Put back the query part
                lien = "%s?%s" % (lien, args)
            return lien

    def __checklink(self, url):
        """Verify the protocol"""
        if url.startswith("http://") or url.startswith("https://"):
            return 0
        else:
            return 1

    def __inzone(self, url):
        """Make sure the url is under the root url"""
        # Returns 0 if the URL is in zone
        if self.scope == self.SCOPE_PAGE:
            if url == self.scopeURL:
                return 0
            else:
                return 1
        if url.startswith(self.scopeURL):
            return 0
        else:
            return 1

    def isExcluded(self, http_resource):
        """Return True if the url is not allowed to be scan"""
        match = False
        for regexp in self.excluded:
            if self.__reWildcard(regexp, http_resource.url):
                match = True
        return match

    def __countMatches(self, http_resource):
        """Return the number of known urls matching the pattern of the given url"""
        matches = 0
        for b in self.browsed:
            if (http_resource.path == b.path and http_resource.method == b.method == "GET"):
                qs = http_resource.encoded_params
                u = b.encoded_params
                if http_resource.encoded_get_keys == b.encoded_get_keys:
                    # key and value in the query string
                    if "=" in qs:
                        i = 0
                        for __ in xrange(0, qs.count("=")):
                            start = qs.find("=", i)
                            i = qs.find("&", start)
                            if i != -1:
                                if u.startswith(qs[:start] + "=") and u.endswith(qs[i:]):
                                    matches += 1
                            else:
                                if u.startswith(qs[:start] + "="):
                                    matches += 1
                else:
                    # only a key name is query string (eg: path?key_name)
                    if "&" not in qs and "&" not in u:
                        matches += 1
        return matches

    def __reWildcard(self, regexp, string):
        """Wildcard-based regular expression system"""
        regexp = re.sub("\*+", "*", regexp)
        match = True
        if regexp.count("*") == 0:
            if regexp == string:
                return True
            else:
                return False
        blocks = regexp.split("*")
        start = ""
        end = ""
        if not regexp.startswith("*"):
            start = blocks[0]
        if not regexp.endswith("*"):
            end = blocks[-1]
        if start != "":
            if string.startswith(start):
                blocks = blocks[1:]
            else:
                return False
        if end != "":
            if string.endswith(end):
                blocks = blocks[:-1]
            else:
                return False
        blocks = [block for block in blocks if block != ""]
        if blocks == []:
            return match
        for block in blocks:
            i = string.find(block)
            if i == -1:
                return False
            string = string[i + len(block):]
        return match

    def go(self, crawlerFile):
        # load of the crawler status if a file is passed to it.
        if crawlerFile is not None:
            if self.persister.isDataForUrl(crawlerFile) == 1:
                self.persister.loadXML(crawlerFile)
                self.tobrowse = self.persister.getToBrose()
                self.browsed = self.persister.getBrowsed()
                self.forms = self.persister.getForms()
                print(_("File {0} loaded, the scan continues:").format(crawlerFile))
                if self.verbose == 2:
                    print(_(" * URLs to browse"))
                    for x in self.tobrowse:
                        print(u"    + {0}".format(x))
                    print(_(" * URLs browsed"))
                    for x in self.browsed:
                        print(u"    + {0}".format(x))
            else:
                print(_("File {0} not found, Wapiti will scan again the web site").format(crawlerFile))

        # while url list isn't empty, continue browsing
        # if the user stop the scan with Ctrl+C, give him all found urls
        # and they are saved in an XML file
        try:
            while len(self.out_of_scope_urls):
                lien = self.out_of_scope_urls.pop(0)
                if self.browse(lien):
                    if self.verbose == 1:
                        sys.stderr.write('.')
                    elif self.verbose == 2:
                        print(lien)

            while len(self.tobrowse):
                lien = self.tobrowse.pop(0)
                if (lien not in self.browsed and lien.url not in self.excluded):
                    if self.browse(lien):
                        if self.verbose == 1:
                            sys.stderr.write('.')
                        elif self.verbose == 2:
                            print(lien)
                        self.browsed.append(lien)

#            if not "link_encoding" in lien.headers:
#              if lien in self.link_encoding:
#                lien.headers["link_encoding"] = self.link_encoding[lien]
#            self.browsed[lien] = lien.headers

            self.saveCrawlerData()
            print('')
            print(_(" Note"))
            print("========")
            print(_("This scan has been saved in the file {0}/{1}.xml").format(self.persister.CRAWLER_DATA_DIR,
                                                                               self.server))
            print(_("You can use it to perform attacks without scanning again the web site with the \"-k\" parameter"))
        except KeyboardInterrupt:
            self.saveCrawlerData()
            print('')
            print(_(" Note"))
            print("========")
            print(_("Scan stopped, the data has been saved"
                    "in the file {0}/{1}.xml").format(self.persister.CRAWLER_DATA_DIR, self.server))
            print(_("To continue this scan, you should launch Wapiti with the \"-i\" parameter"))
            pass

    def verbosity(self, vb):
        """Set verbosity level"""
        self.verbose = vb

    def printLinks(self):
        """Print found URLs on standard output"""
        self.browsed.sort()
        sys.stderr.write("\n+ " + _("URLs") + ":\n")
        for lien in self.browsed:
            print(lien)

    def printForms(self):
        """Print found forms on standard output"""
        if self.forms != []:
            sys.stderr.write("\n+ "+_("Forms Info") + ":\n")
            for form in self.forms:
                print(_("From: {0}").format(form[2]))
                print(_("To: {0}").format(form[0]))
                for k, v in form[1].items():
                    print(u"\t{0} : {1}".format(k, v))
                print('')

    def printUploads(self):
        """Print urls accepting uploads"""
        if self.uploads != []:
            sys.stderr.write("\n+ " + _("Upload Scripts") + ":\n")
            for up in self.uploads:
                print(up)

    def exportXML(self, filename, encoding="UTF-8"):
        "Export the urls and the forms found in an XML file."
        xml = minidom.Document()
        items = xml.createElement("items")
        xml.appendChild(items)

        for lien in self.browsed:
            get = xml.createElement("get")
            get.setAttribute("url", lien.url)
            items.appendChild(get)

        for form in self.forms:
            post = xml.createElement("post")
            post.setAttribute("url", form[0])
            post.setAttribute("referer", form[2])

            for k, v in form[1].items():
                var = xml.createElement("var")
                var.setAttribute("name", k)
                var.setAttribute("value", v)
                post.appendChild(var)
            items.appendChild(post)

        fd = open(filename, "w")
        xml.writexml(fd, "    ", "    ", "\n", encoding)
        fd.close()

    def getLinks(self):
        return self.browsed

    def getForms(self):
        return self.forms

    def getUploads(self):
        self.uploads.sort()
        return self.uploads

    def saveCrawlerData(self):
        self.persister.setRootURL(self.root)
        self.persister.setToBrose(self.tobrowse)
        self.persister.setBrowsed(self.browsed)
        self.persister.setForms(self.forms)
        self.persister.setUploads(self.uploads)
        self.persister.saveXML(os.path.join(self.persister.CRAWLER_DATA_DIR, self.server + '.xml'))


class linkParser(HTMLParser.HTMLParser):
    """Extract urls in 'a' href HTML tags"""
    def __init__(self, url=""):
        HTMLParser.HTMLParser.__init__(self)
        self.liens = []
        self.forms = []
        self.form_values = []
        self.inform = 0
        self.inscript = 0
        self.current_form_url = url
        self.uploads = []
        self.current_form_method = "get"
        self.url = url
        self.__defaults = {'checkbox':       'default',
                           'color':          '%23adeadb',
                           'date':           '2011-06-08',
                           'datetime':       '2011-06-09T20:35:34.32',
                           'datetime-local': '2011-06-09T22:41',
                           'file':           ['pix.gif', 'GIF89a'],
                           'hidden':         'default',
                           'email':           'wapiti%40mailinator.com',
                           'month':          '2011-06',
                           'number':         '1337',
                           'password':       'letmein',
                           'radio':          'beton',
                           'range':          '37',
                           'search':         'default',
                           'submit':         'submit',
                           'tel':            '0606060606',
                           'text':           'default',
                           'time':           '13:37',
                           'url':            'http://wapiti.sf.net/',
                           'week':           '2011-W24'
                           }
        # This is ugly but let's keep it while there is not a js parser
        self.common_js_strings = ["Msxml2.XMLHTTP", "application/x-www-form-urlencoded", ".php", "text/xml",
                                  "about:blank", "Microsoft.XMLHTTP", "text/plain", "text/javascript",
                                  "application/x-shockwave-flash"]

    def handle_starttag(self, tag, attrs):
        tmpdict = {}
        val = None
        for k, v in attrs:
            if v is None:
                continue
            if not k.lower() in tmpdict:
                tmpdict[k.lower()] = v
        if tag.lower() in ['a', 'link']:
            if "href" in tmpdict:
                if tmpdict['href'].lower().startswith("javascript:"):
                    self.liens.extend(lamejs.lamejs(tmpdict["href"].split(':', 1)[1]).getLinks())
                else:
                    self.liens.append(tmpdict['href'])

        if tag.lower() == 'form':
            self.inform = 1
            self.form_values = []
            self.current_form_url = self.url
            if "action" in tmpdict:
                if tmpdict['action'].lower().startswith("javascript"):
                    self.liens.extend(lamejs.lamejs(tmpdict["action"].split(':', 1)[1]).getLinks())
                self.liens.append(tmpdict['action'])
                self.current_form_url = tmpdict['action']

            # Forms use GET method by default
            self.current_form_method = "get"
            if "method" in tmpdict:
                if tmpdict["method"].lower() == "post":
                    self.current_form_method = "post"

        if tag.lower() == 'input':
            if self.inform == 1:
                if "type" not in tmpdict:
                    tmpdict["type"] = "text"
                if "name" in tmpdict:
                    if tmpdict['type'].lower() in self.__defaults:
                        # use the value from the form or use our default value
                        if "value" in tmpdict and tmpdict["value"] != "":
                            val = tmpdict["value"]
                        else:
                            val = self.__defaults[tmpdict['type'].lower()]
                        self.form_values.append([tmpdict['name'], val])

                    if tmpdict['type'].lower() == "image":
                        self.form_values.append([tmpdict['name'] + ".x", "1"])
                        self.form_values.append([tmpdict['name'] + ".y", "1"])

            if "formaction" in tmpdict:
                self.liens.append(tmpdict['formaction'])

        if tag.lower() in ["textarea", "select"]:
            if self.inform == 1:
                if "name" in tmpdict:
                    self.form_values.append([tmpdict['name'], u'on'])

        if tag.lower() in ["frame", "iframe"]:
            if "src" in tmpdict:
                self.liens.append(tmpdict['src'])

        if tag.lower() in ["img", "embed", "track", "source"]:
            if "src" in tmpdict:
                if "?" in tmpdict['src'] or tmpdict['src'].endswith(".swf"):
                    self.liens.append(tmpdict['src'])

        if tag.lower() == "script":
            self.inscript = 1
            if "src" in tmpdict:
                # if "?" in tmpdict['src']:
                self.liens.append(tmpdict['src'])

        if tag.lower() == "meta":
            if "http-equiv" in tmpdict and "content" in tmpdict:
                if tmpdict["http-equiv"].lower() == "refresh":
                    content_str = tmpdict["content"].lower()
                    url_eq_idx = content_str.find("url=")
                    if url_eq_idx >= 0:
                        self.liens.append(tmpdict["content"][url_eq_idx + 4:])

    def handle_endtag(self, tag):
        if tag.lower() == 'form':
            self.inform = 0
            if self.current_form_method == "post":
                self.forms.append((self.current_form_url, self.form_values))
            else:
                l = ["=".join([k, v]) for k, v in self.form_values]
                l.sort()
                self.liens.append(self.current_form_url.split("?")[0] + "?" + "&".join(l))
        if tag.lower() == 'script':
            self.inscript = 0

    def handle_data(self, data):
        if self.inscript:
            self.liens.extend(lamejs.lamejs(data).getLinks())
            candidates = re.findall(r'"([A-Za-z0-9_=#&%\.\+\?/-]*)"', data)
            candidates += re.findall(r"'([A-Za-z0-9_=#&%\.\+\?/-]*)'", data)
            for jstr in candidates:
                if ('/' in jstr or '.' in jstr or '?' in jstr) and jstr not in self.common_js_strings:
                    self.liens.append(jstr)


class linkParser2(object):
    verbose = 0

    """Extract urls in 'a' href HTML tags"""
    def __init__(self, url="", verb=0):
        self.liens = []
        self.forms = []
        self.form_values = []
        self.inform = 0
        self.current_form_url = ""
        self.uploads = []
        self.current_form_method = "get"
        self.verbose = verb

    def __findTagAttributes(self, tag):
        attDouble = re.findall('<\w*[ ]| *(.*?)[ ]*=[ ]*"(.*?)"[ +|>]', tag)
        attSingle = re.findall('<\w*[ ]| *(.*?)[ ]*=[ ]*\'(.*?)\'[ +|>]', tag)
        attNone = re.findall('<\w*[ ]| *(.*?)[ ]*=[ ]*["|\']?(.*?)["|\']?[ +|>]', tag)
        attNone.extend(attSingle)
        attNone.extend(attDouble)
        return attNone

    def feed(self, htmlSource):
        htmlSource = htmlSource.replace("\n", "")
        htmlSource = htmlSource.replace("\r", "")
        htmlSource = htmlSource.replace("\t", "")

        links = re.findall('<a.*?>', htmlSource)
        linkAttributes = []
        for link in links:
            linkAttributes.append(self.__findTagAttributes(link))

        #Finding all the forms: getting the text from "<form..." to "...</form>"
        #the array forms will contain all the forms of the page
        forms = re.findall('<form.*?>.*?</form>', htmlSource)
        formsAttributes = []
        for form in forms:
            formsAttributes.append(self.__findTagAttributes(form))

        #Processing the forms, obtaining the method and all the inputs
        #Also finding the method of the forms
        inputsInForms = []
        textAreasInForms = []
        selectsInForms = []
        for form in forms:
            inputsInForms.append(re.findall('<input.*?>', form))
            textAreasInForms.append(re.findall('<textarea.*?>', form))
            selectsInForms.append(re.findall('<select.*?>', form))

        #Extracting the attributes of the <input> tag as XML parser
        inputsAttributes = []
        for i in xrange(len(inputsInForms)):
            inputsAttributes.append([])
            for inputt in inputsInForms[i]:
                inputsAttributes[i].append(self.__findTagAttributes(inputt))

        selectsAttributes = []
        for i in xrange(len(selectsInForms)):
            selectsAttributes.append([])
            for select in selectsInForms[i]:
                selectsAttributes[i].append(self.__findTagAttributes(select))

        textAreasAttributes = []
        for i in xrange(len(textAreasInForms)):
            textAreasAttributes.append([])
            for textArea in textAreasInForms[i]:
                textAreasAttributes[i].append(self.__findTagAttributes(textArea))

        if self.verbose == 3:
            print('')
            print('')
            print(_("Forms"))
            print("=====")
            for i in xrange(len(forms)):
                print(_("Form {0}").format(str(i)))
                tmpdict = {}
                for k, v in dict(formsAttributes[i]).items():
                    tmpdict[k.lower()] = v
                print(_(" * Method:  {0}").format(self.__decode_htmlentities(tmpdict['action'])))
                print(_(" * Intputs:"))
                for j in xrange(len(inputsInForms[i])):
                    print(u"    + " + inputsInForms[i][j])
                    for att in inputsAttributes[i][j]:
                        print(u"       - " + str(att))
                print(_(" * Selects:"))
                for j in xrange(len(selectsInForms[i])):
                    print(u"    + " + selectsInForms[i][j])
                    for att in selectsAttributes[i][j]:
                        print(u"       - " + str(att))
                print(_(" * TextAreas:"))
                for j in xrange(len(textAreasInForms[i])):
                    print(u"    + " + textAreasInForms[i][j])
                    for att in textAreasAttributes[i][j]:
                        print(u"       - " + str(att))
            print('')
            print(_("URLS"))
            print("====")

        for i in xrange(len(links)):
            tmpdict = {}
            for k, v in dict(linkAttributes[i]).items():
                tmpdict[k.lower()] = v
            if "href" in tmpdict:
                self.liens.append(self.__decode_htmlentities(tmpdict['href']))
                if(self.verbose == 3):
                    print(self.__decode_htmlentities(tmpdict['href']))

        for i in xrange(len(forms)):
            tmpdict = {}
            for k, v in dict(formsAttributes[i]).items():
                tmpdict[k.lower()] = v
            self.form_values = []
            if "action" in tmpdict:
                self.liens.append(self.__decode_htmlentities(tmpdict['action']))
                self.current_form_url = self.__decode_htmlentities(tmpdict['action'])

            # Forms use GET method by default
            self.current_form_method = "get"
            if "method" in tmpdict:
                if tmpdict["method"].lower() == "post":
                    self.current_form_method = "post"

            for j in xrange(len(inputsAttributes[i])):
                tmpdict = {}
                for k, v in dict(inputsAttributes[i][j]).items():
                    tmpdict[k.lower()] = v
                    if "type" not in tmpdict:
                        tmpdict["type"] = "text"
                    if "name" in tmpdict:
                        if tmpdict['type'].lower() in \
                            ['text', 'password', 'radio', 'checkbox', 'hidden',
                             'submit', 'search']:
                            # use default value if present or set it to 'on'
                            if "value" in tmpdict:
                                if tmpdict["value"] != "":
                                    val = tmpdict["value"]
                                else:
                                    val = u"on"
                            else:
                                val = u"on"
                            self.form_values.append([tmpdict['name'], val])
                        if tmpdict['type'].lower() == "file":
                            self.uploads.append(self.current_form_url)

            for j in xrange(len(textAreasAttributes[i])):
                tmpdict = {}
                for k, v in dict(textAreasAttributes[i][j]).items():
                    tmpdict[k.lower()] = v
                if "name" in tmpdict:
                    self.form_values.append([tmpdict['name'], u'on'])

            for j in xrange(len(selectsAttributes[i])):
                tmpdict = {}
                for k, v in dict(selectsAttributes[i][j]).items():
                    tmpdict[k.lower()] = v
                if "name" in tmpdict:
                    self.form_values.append([tmpdict['name'], u'on'])

            if self.current_form_method == "post":
                self.forms.append((self.current_form_url, self.form_values))
            else:
                l = ["=".join([k, v]) for k, v in self.form_values]
                l.sort()
                self.liens.append(self.current_form_url.split("?")[0] + "?" + "&".join(l))

    def __substitute_entity(self, match):
        ent = match.group(2)
        if match.group(1) == "#":
            return unichr(int(ent))
        else:
            cp = n2cp.get(ent)

            if cp:
                return unichr(cp)
            else:
                return match.group()

    def __decode_htmlentities(self, string):
        entity_re = re.compile("&(#?)(\d{1,5}|\w{1,8});")
        return entity_re.subn(self.__substitute_entity, string)[0]

    def reset(self):
        self.liens = []
        self.forms = []
        self.form_values = []
        self.inform = 0
        self.current_form_url = ""
        self.uploads = []
        self.current_form_method = "get"

if __name__ == "__main__":
    def _(text):
        return text
    try:
        auth = []
        xmloutput = ""
        crawlerFile = None

        if len(sys.argv) < 2:
            print(lswww.__doc__)
            sys.exit(0)
        if '-h' in sys.argv or '--help' in sys.argv:
            print(lswww.__doc__)
            sys.exit(0)
        myls = lswww(sys.argv[1])
        myls.verbosity(1)
        try:
            opts, args = getopt.getopt(sys.argv[2:],
                                       "hp:s:x:c:a:r:v:t:n:e:ib:",
                                       ["help", "proxy=", "start=", "exclude=", "cookie=", "auth=",
                                        "remove=", "verbose=", "timeout=", "nice=", "export=", "continue",
                                        "scope="])
        except getopt.GetoptError, e:
            print(e)
            sys.exit(2)
        for o, a in opts:
            if o in ("-h", "--help"):
                print(lswww.__doc__)
                sys.exit(0)
            if o in ("-s", "--start"):
                if a.startswith("http://") or a.startswith("https://"):
                    myls.addStartURL(a)
            if o in ("-x", "--exclude"):
                if a.startswith("http://") or a.startswith("https://"):
                    myls.addExcludedURL(a)
            if o in ("-p", "--proxy"):
                    myls.setProxy(a)
            if o in ("-c", "--cookie"):
                myls.setCookieFile(a)
            if o in ("-r", "--remove"):
                myls.addBadParam(a)
            if o in ("-a", "--auth"):
                if "%" in a:
                    auth = [a.split("%")[0], a.split("%")[1]]
                    myls.setAuthCredentials(auth)
            if o in ("-v", "--verbose"):
                if str.isdigit(a):
                    myls.verbosity(int(a))
            if o in ("-t", "--timeout"):
                if str.isdigit(a):
                    myls.setTimeOut(int(a))
            if o in ("-n", "--nice"):
                if str.isdigit(a):
                    myls.setNice(int(a))
            if o in ("-e", "--export"):
                xmloutput = a
            if o in ("-b", "--scope"):
                myls.setScope(a)
            if o in ("-i", "--continue"):
                crawlerPersister = CrawlerPersister()
                crawlerFile = os.path.join(crawlerPersister.CRAWLER_DATA_DIR, sys.argv[1].split("://")[1] + '.xml')
        try:
            opts, args = getopt.getopt(sys.argv[2:],
                                       "hp:s:x:c:a:r:v:t:n:e:i:b:",
                                       ["help", "proxy=", "start=", "exclude=", "cookie=",
                                        "auth=", "remove=", "verbose=", "timeout=", "nice=",
                                        "export=", "continue=", "scope="])
        except getopt.GetoptError, e:
            ""
        for o, a in opts:
            if o in ("-i", "--continue"):
                if a != '' and a[0] != '-':
                    crawlerFile = a

        myls.go(crawlerFile)
        myls.printLinks()
        myls.printForms()
        myls.printUploads()
        if xmloutput != "":
            myls.exportXML(xmloutput)
    except SystemExit:
        pass
