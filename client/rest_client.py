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

import re
import sys
import urllib

from rest import RESTClient

def format_path(path):
    """Normalize path for use with the Faucet API.
    """
    if not path:
        return path

    path = re.sub(r'/+', '/', path)

    if path == '/':
        return (u"" if isinstance(path, unicode) else "")
    else:
        return '/' + path.strip('/')


def build_path(target, params=None):
    if sys.version_info < (3,) and type(target) == unicode:
        target = target.encode("utf8")

    target_path = urllib.quote(target)

    params = params or {}
    params = params.copy()

    if params:
        return "/%s?%s" % (target_path, urllib.urlencode(params))
    else:
        return "/%s" % (target_path)


def build_url(host, target, params=None):
    return "http://%s%s" % (host, build_path(target, params))


class FailedParseActionException(Exception):
    message = '%(msg)s'


class NotSupportedException(Exception):
    message = '%(msg)s'


class FaucetClient(object):

    SUPPORTED_ACTIONS = ['accept', 'mark-packet']

    SUPPORTED_QUEIES = ['dst-address', 'src-address', \
        'dst-port', 'src-port', 'new-packet-mark', \
        'queue', 'packet-mark', 'chain']

    def __init__(self, host, rest_client=RESTClient):
        self.rest_client = rest_client
        self.host = host

    def get_flow_status(self, switch=None):
        path = 'faucet/status'
        if len(switch):
            path += '/%s' % (switch)
        params = None
        url, params = self.request(path, params, method='GET')
        return self.rest_client.GET(url)

    def set_action(self, action, switch=None):
        path = 'faucet/action'
        if len(switch):
            path += '/%s' % (switch)
        params = self._action_parse(action) 
        url, params = self.request(path, params, method='POST')
        return self.rest_client.POST(url, params)

    def _action_parse(self, action):
        operations = action.split(' ')
        if not len(operations):
            raise FailedParseActionException(msg='Can not \
                parse actions:%s' % action)

        inst = operations[0]
        if inst not in FaucetClient.SUPPORTED_ACTIONS:
            raise NotSupportedException(msg='Not \
              supported action :%s' % inst)
        
        query = operations[1]
        query_list = query.split(',')
        property_dict = {'action': inst}
        for query in query_list:
            param = query.split('=')
            if len(param) != 2:
                raise FailedParseActionException(msg='Can \
                    not parse actions:%s' % query)
            key = param[0]
            value = param[1]
            if key not in FaucetClient.SUPPORTED_QUEIES:
                raise NotSupportedException(msg='Not \
                    supported query :%s' % query)
            property_dict[key] = value

        return property_dict


    def request(self, target, params=None, method='POST',
            content_server=False):
        assert method in ['GET','POST', 'PUT'], "Only 'GET', 'POST', and 'PUT' are allowed."
        if params is None:
            params = {}

        if method in ('GET', 'PUT'):
            url = build_url(self.host, target, params)
        else:
            url = build_url(self.host, target)

        return url, params 

