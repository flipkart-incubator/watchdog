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
import urllib
import urlparse
import socket
import os
import cgi
import requests
import datetime
from wapitiCore.net import jsoncookie
from copy import deepcopy


def shell_escape(s):
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('$', '\\$')
    s = s.replace('!', '\\!')
    s = s.replace('`', '\\`')
    return s


class HTTPResource(object):
    _method = "GET"
    _encoding = "ISO-8859-1"
    _hostname = ""
    _resource_path = ""
    _file_path = ""
    _status = 0
    _headers = {}
    _referer = ""
    _start_time = None
    _elapsed_time = None
    _port = 80

    # Most of the members of a HTTPResource object are immutable so we compute
    # the data only one time (when asked for) and we keep it in memory for less
    # calculations in those "cached" vars.
    _cached_url = None
    _cached_get_keys = None
    _cached_post_keys = None
    _cached_file_keys = None
    _cached_encoded_params = None
    _cached_encoded_data = None
    _cached_encoded_files = None
    _cached_hash = None

    # eg: get = [['id', '25'], ['color', 'green']]
    _get_params = []

    # same structure as _get_params
    _post_params = []

    # eg: files = [['file_field', ('file_name', 'file_content')]]
    _file_params = []

    def __init__(self, path, method="", get_params=None, post_params=None,
                 encoding="UTF-8", referer="", file_params=None):
        """Create a new HTTPResource object.

        Takes the following arguments:
            path : The path of the HTTP resource on the server. It can contain a query string.
            get_params : A list of key/value parameters (each one is a list of two string).
                                      Each string should already be urlencoded in the good encoding format.
            post_params : Same structure as above but specify the parameters sent in the HTTP body.
            file_params : Same as above expect the values are a tuple (filename, file_content).
            encoding : A string specifying the encoding used to send data to this URL.
                                  Don't mistake it with the encoding of the webpage pointed out by the HTTPResource.
            referer : The URL from which the current HTTPResource was found.
        """
        self._resource_path = path

        if post_params is None:
            self._post_params = []
        elif isinstance(post_params, list):
            self._post_params = deepcopy(post_params)
        elif isinstance(post_params, basestring):
            self._post_params = []
            if len(post_params):
                for kv in post_params.split("&"):
                    if kv.find("=") > 0:
                        self._post_params.append(kv.split("=", 1))
                    else:
                        # ?param without value
                        self._post_params.append([kv, None])

        if file_params is None:
            self._file_params = []
        elif isinstance(file_params, list):
            self._file_params = deepcopy(file_params)
        else:
            self._file_params = file_params

        if get_params is None:
            self._get_params = []
            if "?" in self._resource_path:
                query_string = urlparse.urlparse(self._resource_path).query
                for kv in query_string.split("&"):
                    if kv.find("=") > 0:
                        self._get_params.append(kv.split("=", 1))
                    else:
                        # ?param without value
                        self._get_params.append([kv, None])
                self._resource_path = self._resource_path.split("?")[0]
        elif isinstance(get_params, list):
            self._get_params = deepcopy(get_params)
        else:
            self._get_params = get_params

        if not method:
            # For lazy
            if self._post_params or self._file_params:
                self._method = "POST"
            else:
                self._method = "GET"
        else:
            self._method = method
        self._encoding = encoding
        self._referer = referer
        parsed = urlparse.urlparse(self._resource_path)
        self._file_path = parsed.path
        self._hostname = parsed.netloc
        if parsed.port is not None:
            self._port = parsed.port
        elif parsed.scheme == "https":
            self._port = 443

    def __hash__(self):
        if self._cached_hash is None:
            get_kv = tuple([tuple(param) for param in self._get_params])
            post_kv = tuple([tuple(param) for param in self._post_params])
            file_kv = tuple([tuple([param[0], param[1][0]]) for param in self._file_params])

            self._cached_hash = hash((self._method, self._resource_path,
                                      get_kv, post_kv, file_kv))
        return self._cached_hash

    def __eq__(self, other):
        if not isinstance(other, HTTPResource):
            return NotImplemented

        if self._method != other._method:
            return False

        if self._resource_path != other._resource_path:
            return False

        return hash(self) == hash(other)

    def __lt__(self, other):
        if not isinstance(other, HTTPResource):
            return NotImplemented
        if self.url < other.url:
            return True
        else:
            if self.url == other.url:
                return self.encoded_data < other.encoded_data
            return False

    def __le__(self, other):
        if not isinstance(other, HTTPResource):
            return NotImplemented
        if self.url < other.url:
            return True
        elif self.url == other.url:
            return self.encoded_data <= other.encoded_data
        return False

    def __ne__(self, other):
        if not isinstance(other, HTTPResource):
            return NotImplemented

        if self.method != other.method:
            return True

        if self._resource_path != other._resource_path:
            return True

        return hash(self) != hash(other)

    def __gt__(self, other):
        if not isinstance(other, HTTPResource):
            return NotImplemented
        if self.url > other.url:
            return True
        elif self.url == other.url:
            return self.encoded_data > other.encoded_data
        return False

    def __ge__(self, other):
        if not isinstance(other, HTTPResource):
            return NotImplemented
        if self.url > other.url:
            return True
        elif self.url == other.url:
            return self.encoded_data >= other.encoded_data
        return False

    def _encoded_keys(self, params):
        quoted_keys = []
        for k, __ in params:
            quoted_keys.append(urllib.quote(k, safe='%'))
        return "&".join(quoted_keys)

    def __repr__(self):
        buff = ""
        if self._get_params:
            buff = "%s %s" % (self._method, self.url)
        else:
            buff = "%s %s" % (self._method, self._resource_path)
        if self._post_params:
            buff += "\n\tdata = %s" % (self.encoded_data)
        if self._file_params:
            buff += "\n\tfiles = %s" % (self.encoded_files)
        return buff

    @property
    def http_repr(self):
        rel_url = self.url.split('/', 3)[3]
        http_string = "%s /%s HTTP/1.1\nHost: %s\n" % (self._method,
                                                       rel_url,
                                                       self._hostname)
        if self._referer:
            http_string += "Referer: %s\n" % (self._referer)
        if self._file_params:
            boundary = "------------------------boundarystring"
            http_string += "Content-Type: multipart/form-data; boundary=%s\n\n" % (boundary)
            for field_name, field_value in self._post_params:
                http_string += ("{0}\nContent-Disposition: form-data; "
                                "name=\"{1}\"\n\n{2}\n").format(boundary, field_name, field_value)
            for field_name, field_value in self._file_params:
                http_string += ("{0}\nContent-Disposition: form-data; name=\"{1}\"; filename=\"{2}\"\n\n"
                                "/* snip file content snip */\n").format(boundary, field_name, field_value[0])
            http_string += "{0}--\n".format(boundary)
        elif self._post_params:
            http_string += "Content-Type: application/x-www-form-urlencoded\n"
            http_string += "\n%s" % (self.encoded_data)

        return http_string

    @property
    def curl_repr(self):
        curl_string = "curl \"{0}\"".format(shell_escape(self.url))
        if self._referer:
            curl_string += " -e \"{0}\"".format(shell_escape(self._referer))
        if self._file_params:
            for field_name, field_value in self._post_params:
                curl_string += " -F \"{0}\"".format(shell_escape("{0}={1}".format(field_name, field_value)))
            for field_name, field_value in self._file_params:
                curl_upload_kv = "{0}=@your_local_file;filename={1}".format(field_name, field_value[0])
                curl_string += " -F \"{0}\"".format(shell_escape(curl_upload_kv))
            pass
        elif self._post_params:
            curl_string += " -d \"{0}\"".format(shell_escape(self.encoded_data))

        return curl_string

    def setHeaders(self, response_headers):
        """Set the HTTP headers received while requesting the resource"""
        self._headers = response_headers

    def setStartTime(self):
        self._start_time = datetime.datetime.utcnow()

    def setElapsedTime(self):
        """Store the time taken for obtaining a responde to the request."""
        self._elapsed_time = datetime.datetime.utcnow() - self._start_time

    @property
    def start_time(self):
        return self._start_time

    @property
    def elapsed_time(self):
        return self._elapsed_time

    @property
    def url(self):
        if self._cached_url is None:
            if self._get_params:
                self._cached_url = "{0}?{1}".format(self._resource_path,
                                                    self._encode_params(self._get_params))
            else:
                self._cached_url = self._resource_path
        return self._cached_url

    @property
    def hostname(self):
        return self._hostname

    @property
    def port(self):
        return self._port

    @property
    def path(self):
        return self._resource_path

    @property
    def file_path(self):
        return self._file_path

    @property
    def file_ext(self):
        return os.path.splitext(self.file_path)[1]

    @property
    def file_name(self):
        return os.path.basename(self.file_path)

    @property
    def method(self):
        return self._method

    @property
    def encoding(self):
        return self._encoding

    @property
    def headers(self):
        return self._headers

    @property
    def referer(self):
        return self._referer

    # To prevent errors, always return a deepcopy of the internal lists
    @property
    def get_params(self):
        return deepcopy(self._get_params)

    @property
    def post_params(self):
        return deepcopy(self._post_params)

    @property
    def file_params(self):
        return deepcopy(self._file_params)

    def _encode_params(self, params):
        if not params:
            return ""

        key_values = []
        for k, v in params:
            k = urllib.quote(k, safe='%')
            if v is None:
                key_values.append(k)
            else:
                if isinstance(v, tuple) or isinstance(v, list):
                    # for upload fields
                    v = v[0]
                v = urllib.quote(v, safe='%')
                key_values.append("%s=%s" % (k, v))
        return "&".join(key_values)

    @property
    def encoded_params(self):
        return self._encode_params(self._get_params)

    @property
    def encoded_data(self):
        """Return a raw string of key/value parameters for POST requests"""
        return self._encode_params(self._post_params)

    @property
    def encoded_files(self):
        return self._encode_params(self._file_params)

    @property
    def encoded_get_keys(self):
        if self._cached_get_keys is None:
            self._cached_get_keys = self._encoded_keys(self._get_params)
        return self._cached_get_keys

    @property
    def encoded_post_keys(self):
        if self._cached_post_keys is None:
            self._cached_post_keys = self._encoded_keys(self._post_params)
        return self._cached_post_keys

    @property
    def encoded_file_keys(self):
        if self._cached_file_keys is None:
            self._cached_file_keys = self._encoded_keys(self._file_params)
        return self._cached_file_keys


class HTTPResponse(object):
    resp = None

    def __init__(self, requests_resp, peer, timestamp):
        self.resp = requests_resp
        self.peer = peer
        self.timestamp = timestamp

    def getPage(self):
        "Return the content of the page in unicode."
        if self.resp.encoding:
            return self.resp.text
        else:
            return self.resp.content

    def getRawPage(self):
        "Return the content of the page in raw bytes."
        return self.resp.content

    def getCode(self):
        "Return the HTTP Response code ."
        return str(self.resp.status_code)

    def getHeaders(self):
        "Return the HTTP headers of the Response."
        return self.resp.headers

    def getPageCode(self):
        "Return a tuple of the content and the HTTP Response code."
        return (self.getPage(), self.getCode())

    def getEncoding(self):
        "Return the detected encoding for the page."
        return self.resp.encoding

    def setEncoding(self, new_encoding):
        "Change the encoding (for getPage())"
        self.resp.encoding = new_encoding

    def getPeer(self):
        """Return the network address of the server that delivered this Response.
        This will always be a socket_object.getpeername() return value, which is
        normally a (ip_address, port) tuple."""
        return self.peer

    def getTimestamp(self):
        """Return a datetime.datetime object describing when this response was
        received."""
        return self.timestamp


class HTTP(object):
    proxies = {}
    auth_credentials = []
    auth_method = "basic"
    timeout = 6.0
    h = None
    cookiejar = {}
    server = ""
    verify_ssl = False

    configured = 0

    def __init__(self, server):
        self.h = requests.Session()
        for adapter_protocol in self.h.adapters:
            self.h.adapters[adapter_protocol].max_retries = 1
        self.server = server

    def send(self, target, method="",
             get_params=None, post_params=None, file_params=None,
             headers={}):
        "Send a HTTP Request. GET or POST (if post_params is set)."
        resp = None
        _headers = {}
        _headers.update(headers)

        get_data = None
        if isinstance(get_params, basestring):
            get_data = get_params
        elif isinstance(get_params, list):
            get_data = self.encode(get_params)

        post_data = None
        if isinstance(post_params, basestring):
            post_data = post_params
        elif isinstance(post_params, list):
            post_data = self.encode(post_params)

        file_data = None
        if isinstance(file_params, tuple) or isinstance(file_params, list):
            file_data = file_params

        if isinstance(target, HTTPResource):
            if get_data is None:
                get_data = target.get_params

            target.setStartTime()
            if target.method == "GET":
                resp = self.h.get(target.url,
                                  headers=_headers,
                                  timeout=self.timeout,
                                  allow_redirects=True,
                                  verify=self.verify_ssl)
            else:
                if target.referer:
                    _headers.update({'referer': target.referer})
                if post_data is None:
                    post_data = target.post_params
                if file_data is None:
                    file_data = target.file_params
                if target.method == "POST":
                    if not file_data:
                        _headers.update({'content-type': 'application/x-www-form-urlencoded'})

                    resp = self.h.post(target.path,
                                       params=get_data,
                                       data=post_data,
                                       files=file_data,
                                       headers=_headers,
                                       timeout=self.timeout,
                                       allow_redirects=True,
                                       verify=self.verify_ssl)
                else:
                    resp = self.h.request(target.method,
                                          target.path,
                                          params=get_data,
                                          data=post_data,
                                          files=file_data,
                                          headers=_headers,
                                          timeout=self.timeout,
                                          allow_redirects=True,
                                          verify=self.verify_ssl)
            target.setElapsedTime()
            target.setHeaders(resp.headers)

        if resp is None:
            return None
        return HTTPResponse(resp, "", datetime.datetime.now())

    def quote(self, url):
        "Encode a string with hex representation (%XX) for special characters."
        return urllib.quote(url)

    def encode(self, params_list):
        "Encode a sequence of two-element lists or dictionary into a URL query string."
        encoded_params = []
        for k, v in params_list:
            # not safe: '&=#' with of course quotes...
            k = urllib.quote(k, safe='/%[]:;$()+,!?*')
            v = urllib.quote(v, safe='/%[]:;$()+,!?*')
            encoded_params.append("%s=%s" % (k, v))
        return "&".join(encoded_params)

    def uqe(self, params_list):  # , encoding = None):
        "urlencode a string then interpret the hex characters (%41 will give 'A')."
        return urllib.unquote(self.encode(params_list))  # , encoding))

    def escape(self, url):
        "Change special characters in their html entities representation."
        return cgi.escape(url, quote=True).replace("'", "%27")

    def setTimeOut(self, timeout=6.0):
        "Set the time to wait for a response from the server."
        self.timeout = timeout
        socket.setdefaulttimeout(self.timeout)

    def getTimeOut(self):
        "Return the timeout used for HTTP requests."
        return self.timeout

    def setVerifySsl(self, verify=True):
        "Set whether SSL must be verified."
        self.verify_ssl = verify

    def setProxy(self, proxy=""):
        "Set a proxy to use for HTTP requests."
        url_parts = urlparse.urlparse(proxy)
        protocol = url_parts.scheme
        host = url_parts.netloc
        if protocol in ["http", "https"]:
            if host:
                self.proxies[protocol] = "%s://%s/" % (protocol, host)
        self.h.proxies = self.proxies

    def setCookieFile(self, cookie):
        "Load session data from a cookie file"
        if os.path.isfile(cookie):
            jc = jsoncookie.jsoncookie()
            jc.open(cookie)
            self.cookiejar = jc.cookiejar(self.server)
            self.h.cookies = self.cookiejar
            jc.close()

    def setAuthCredentials(self, auth_credentials):
        "Set credentials to use if the website require an authentication."
        self.auth_credentials = auth_credentials
        # Force reload
        self.setAuthMethod(self.auth_method)

    def setAuthMethod(self, auth_method):
        "Set the authentication method to use for the requests."
        self.auth_method = auth_method
        if len(self.auth_credentials) == 2:
            username, password = self.auth_credentials
            if self.auth_method == "basic":
                from requests.auth import HTTPBasicAuth
                self.h.auth = HTTPBasicAuth(username, password)
            elif self.auth_method == "digest":
                from requests.auth import HTTPDigestAuth
                self.h.auth = HTTPDigestAuth(username, password)
            elif self.auth_method == "ntlm":
                from requests_ntlm import HttpNtlmAuth
                self.h.auth = HttpNtlmAuth(username, password)
        elif self.auth_method == "kerberos":
            from requests_kerberos import HTTPKerberosAuth
            self.h.auth = HTTPKerberosAuth()

if __name__ == "__main__":
    res1 = HTTPResource("http://httpbin.org/post?var1=a&var2=b",
                        post_params=[['post1', 'c'], ['post2', 'd']])
    res2 = HTTPResource("http://httpbin.org/post?var1=a&var2=z",
                        post_params=[['post1', 'c'], ['post2', 'd']])
    res3 = HTTPResource("http://httpbin.org/post?var1=a&var2=b",
                        post_params=[['post1', 'c'], ['post2', 'z']])
    res4 = HTTPResource("http://httpbin.org/post?var1=a&var2=b",
                        post_params=[['post1', 'c'], ['post2', 'd']])
    res5 = HTTPResource("http://httpbin.org/post?var1=z&var2=b",
                        post_params=[['post1', 'c'], ['post2', 'd']])
    res6 = HTTPResource("http://httpbin.org/post?var3=z&var2=b",
                        post_params=[['post1', 'c'], ['post2', 'd']])
    res7 = HTTPResource("http://httpbin.org/post?var1=z&var2=b&var4=e",
                        post_params=[['post1', 'c'], ['post2', 'd']])
    res8 = HTTPResource("http://httpbin.org/post?var1=z&var2=d",
                        post_params=[['post1', 'c'], ['post2', 'd']])
    res10 = HTTPResource("http://httpbin.org/post?qs0",
                         post_params=[['post1', 'c'], ['post2', 'd']])
    res11 = HTTPResource("http://httpbin.org/post?qs1",
                         post_params=[['post1', 'c'], ['post2', 'd']])
    res12 = HTTPResource("http://httpbin.org/post?qs1",
                         post_params=[['post1', 'c'], ['post2', 'd']],
                         file_params=[['file1', ['fname1', 'content']], ['file2', ['fname2', 'content']]])
    assert res1 < res2
    assert res2 > res3
    assert res1 < res3
    assert res1 == res4
    assert res1 != res2
    assert res2 >= res1
    assert res1 <= res3
    print "=== Basic representation follows ==="
    print res1
    print "=== cURL representation follows ==="
    print res1.curl_repr
    print "=== HTTP representation follows ==="
    print res1.http_repr
    print "=== POST parameters as an array ==="
    print res1.post_params
    print "=== POST keys encoded as string ==="
    print res1.encoded_post_keys
    print "=== Upload HTTP representation  ==="
    print res12.http_repr
    print "=== Upload basic representation ==="
    print res12
    print "=== Upload cURL representation  ==="
    print res12.curl_repr
    print
