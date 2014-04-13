#!/usr/bin/env python
#
# Copyright 2014 cloudysunny14.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import io
import pkg_resources
import socket
import ssl
import sys
import urllib

try:
    import json
except ImportError:
    import simplejson as json

try:
   import urllib3
except ImportError:
    raise ImportError('client requires urllib3.')


SDK_VERSION = "0.1.0"

TRUSTED_CERT_FILE = pkg_resources.resource_filename(__name__, 'trusted-certs.crt')


class RESTResponse(io.IOBase):
    
    def __init__(self, resp):
        self.urllib3_response = resp
        self.status = resp.status
        self.version = resp.version
        self.reason = resp.reason
        self.strict = resp.strict
        self.is_closed = False

    def __del__(self):
        self.close()

    def __exit__(self, typ, value, traceback):
        self.close()

    def read(self, amt=None):
        if self.is_closed:
            raise ValueError('Response already closed')
        return self.urllib3_response.read(amt)

    BLOCKSIZE = 4 * 1024 * 1024 # 4MB at a time just because

    def close(self):
        """Closes the underlying socket."""

        if self.is_closed:
            return

        while self.read(RESTResponse.BLOCKSIZE):
            pass

        self.is_closed = True
        self.urllib3_response.release_conn()

    @property
    def closed(self):
        return self.is_closed


    def getheaders(self):
        """Returns a dictionary of the response headers."""
        return self.urllib3_response.getheaders()

    def getheader(self, name, default=None):
        """Returns a given response header."""
        return self.urllib3_response.getheader(name, default)

    try:
        urllib3.HTTPResponse.flush
        urllib3.HTTPResponse.fileno
        def fileno(self):
            return self.urllib3_response.fileno()
        def flush(self):
            return self.urllib3_response.flush()
    except AttributeError:
        pass

def create_connection(address):
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.connect(sa)
            return sock

        except socket.error as e:
            err = e
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    else:
        raise socket.error("getaddrinfo returns an empty list")

def json_loadb(data):
    if sys.version_info >= (3,):
        data = data.decode('utf8')
    return json.loads(data)


class RESTClientObject(object):
    def __init__(self, max_reusable_connections=8, mock_urlopen=None):
        self.mock_urlopen = mock_urlopen
        self.pool_manager = urllib3.PoolManager(
            num_pools=4,
            maxsize=max_reusable_connections,
            block=False,
            timeout=60.0,
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=TRUSTED_CERT_FILE,
            ssl_version=ssl.PROTOCOL_TLSv1,
        )

    def request(self, method, url, post_params=None, body=None, headers=None, raw_response=False):
        """Performs a REST request. See :meth:`RESTClient.request()` for detailed description."""

        post_params = post_params or {}
        headers = headers or {}
        headers['User-Agent'] = 'faucet/' + SDK_VERSION

        if post_params:
            if body:
                raise ValueError("body parameter cannot be used with post_params parameter")
            body = urllib.urlencode(post_params)
            headers["Content-type"] = "application/x-www-form-urlencoded"

        if hasattr(body, 'getvalue'):
            body = str(body.getvalue())
            headers["Content-Length"] = len(body)

        for key, value in headers.items():
            if isinstance(value, basestring) and '\n' in value:
                raise ValueError("headers should not contain newlines (%s: %s)" %
                                 (key, value))

        try:
            urlopen = self.mock_urlopen if self.mock_urlopen else self.pool_manager.urlopen
            r = urlopen(
                method=method,
                url=url,
                body=body,
                headers=headers,
                preload_content=False
            )
            r = RESTResponse(r)
        except socket.error as e:
            raise RESTSocketError(url, e)
        except urllib3.exceptions.SSLError as e:
            raise RESTSocketError(url, "SSL certificate error: %s" % e)

        if r.status != 200:
            raise ErrorResponse(r, r.read())

        return self.process_response(r, raw_response)

    def process_response(self, r, raw_response):
        if raw_response:
            return r
        else:
            s = r.read()
            try:
                resp = json_loadb(s)
            except ValueError:
                raise ErrorResponse(r, s)
            r.close()

        return resp

    def GET(self, url, headers=None, raw_response=False):
        assert type(raw_response) == bool
        return self.request("GET", url, headers=headers, raw_response=raw_response)

    def POST(self, url, params=None, headers=None, raw_response=False):
        assert type(raw_response) == bool
        if params is None:
            params = {}

        return self.request("POST", url,
                            post_params=params, headers=headers, raw_response=raw_response)

    def POST_BODY(self, url, params=None, headers=None, body=None, raw_response=False):
        assert type(raw_response) == bool
        if params is None:
            params = {}
        return self.request("POST", url, body=body,
                            post_params=params, headers=headers,
                            raw_response=raw_response)

    def PUT(self, url, body, headers=None, raw_response=False):
        assert type(raw_response) == bool
        return self.request("PUT", url, body=body, headers=headers, raw_response=raw_response)


class RESTClient(object):
    IMPL = RESTClientObject()

    @classmethod
    def request(cls, *n, **kw):
        return cls.IMPL.request(*n, **kw)

    @classmethod
    def GET(cls, *n, **kw):
        return cls.IMPL.GET(*n, **kw)

    @classmethod
    def POST(cls, *n, **kw):
        return cls.IMPL.POST(*n, **kw)

    @classmethod
    def PUT(cls, *n, **kw):
        return cls.IMPL.PUT(*n, **kw)

    @classmethod
    def POST_BODY(cls, *n, **kw):
        return cls.IMPL.POST_BODY(*n, **kw)


class RESTSocketError(socket.error):
    
    def __init__(self, host, e):
        msg = "Error connecting to \"%s\": %s" % (host, str(e))
        socket.error.__init__(self, msg)


class _ErrorResponse__doc__(Exception):
    
    _status__doc__ = "HTTP response status (an int)."
    _reason__doc__ = "HTTP response reason (a string)."
    _body__doc__ = "HTTP response body (string or JSON dict)."
    _headers__doc__ = "HTTP response headers (a list of (header, value) tuples)."
    _error_msg__doc__ = "Error message for developer (optional)."
    _user_error_msg__doc__ = "Error message for end user (optional)."


class ErrorResponse(Exception):

    def __init__(self, http_resp, body):
        self.status = http_resp.status
        self.reason = http_resp.reason
        self.body = body
        self.headers = http_resp.getheaders()
        http_resp.close() # won't need this connection anymore

        try:
            self.body = json_loadb(self.body)
            self.error_msg = self.body.get('error')
            self.user_error_msg = self.body.get('user_error')
        except ValueError:
            self.error_msg = None
            self.user_error_msg = None

    def __str__(self):
        if self.user_error_msg and self.user_error_msg != self.error_msg:
            # one is translated and the other is English
            msg = "%r (%r)" % (self.user_error_msg, self.error_msg)
        elif self.error_msg:
            msg = repr(self.error_msg)
        elif not self.body:
            msg = repr(self.reason)
        else:
            msg = "Error parsing response body or headers: " +\
                  "Body - %.100r Headers - %r" % (self.body, self.headers)

        return "[%d] %s" % (self.status, msg)

