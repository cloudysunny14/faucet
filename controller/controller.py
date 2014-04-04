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

import logging
import json
from urlparse import parse_qs

from webob import Response

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.exception import OFPUnknownVersion
from ryu.lib import dpid as dpid_lib
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser

from lib import qoslib 

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

REST_ALL = 'all'
REST_STATUS = 'status'
REST_SWITCHID = 'switch_id'
REST_STATUS_ENABLE = 'enable'
REST_COMMAND_RESULT = 'command_result'
REST_STATUS_DISABLE = 'disable'

STATUS_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX

class Rest(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication,
                 'qoslib': qoslib.QoSLib}

    def __init__(self, *args, **kwargs):
        super(Rest, self).__init__(*args, **kwargs)
        RestController.set_logger(self.logger)

        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.qoslib = kwargs['qoslib']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        requirements = {'switchid': SWITCHID_PATTERN,
                        'vlanid': VLANID_PATTERN}
        mapper = wsgi.mapper
        wsgi.registory['RestController'] = self.data
        path = '/faucet'

        uri = path + '/status'
        mapper.connect('flow', uri,
                       controller=RestController, action='get_all_status',
                       conditions=dict(method=['GET']))

        uri = path + '/status/{switch_id}'
        mapper.connect('flow', uri,
                       controller=RestController, action='get_status',
                       conditions=dict(method=['GET']))

        uri = path + '/action/{switch_id}'
        mapper.connect('mangle', uri,
                       controller=RestController, action='set_action',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        uri = path + '/queue/{switch_id}'
        mapper.connect('queue', uri,
                       controller=RestController, action='queue_status',
                       conditions=dict(method=['GET']))

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
                dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            RestController.regist_ofs(ev.dp, self.qoslib)
        else:
            RestController.unregist_ofs(ev.dp)

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)


class OFSList(dict):
    def __init__(self):
        super(OFSList, self).__init__()

    def get_ofs(self, dp_id):
        if len(self) == 0:
            raise ValueError('firewall sw is not connected.')

        dps = {}
        if dp_id == REST_ALL:
            dps = self
        else:
            try:
                dpid = dpid_lib.str_to_dpid(dp_id)
            except:
                raise ValueError('Invalid switchID.')

            if dpid in self:
                dps = {dpid: self[dpid]}
            else:
                msg = 'firewall sw is not connected. : switchID=%s' % dp_id
                raise ValueError(msg)

        return dps

class RestController(ControllerBase):

    _OFS_LIST = OFSList()
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(RestController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[FAUCET][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @staticmethod
    def regist_ofs(dp, qoslib):
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        try:
            f_ofs = Faucet(dp, qoslib)
        except OFPUnknownVersion, message:
            RestController._LOGGER.info('dpid=%s: %s',
                                         dpid_str, message)
            return

        RestController._OFS_LIST.setdefault(dp.id, f_ofs)

        RestController._LOGGER.info('dpid=%s: Join as firewall.',
                                        dpid_str)

    @staticmethod
    def unregist_ofs(dp):
        if dp.id in RestController._OFS_LIST:
            del RestController._OFS_LIST[dp.id]
            RestController._LOGGER.info('dpid=%s: Leave firewall.',
                                            dpid_lib.dpid_to_str(dp.id))


    # GET /faucet/status
    def get_all_status(self, req, **_kwargs):
        return self._access_module(REST_ALL, 'get_status',
                                   waiters=self.waiters)

    # GET /faucet/status/{switch_id}
    def get_status(self, req, switch_id, **_kwargs):
        return self._access_module(switch_id, 'get_status',
                                   waiters=self.waiters)

    # POST /faucet/mangle/action/{switch_id}
    def set_action(self, req, switch_id, **_kwargs):
        return self._set_action(req, switch_id)


    def _access_module(self, switchid, func, waiters=None):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            function = getattr(f_ofs, func)
            msg = function() if waiters is None else function(waiters)
            msgs.append(msg)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)


    def _set_action(self, req, switchid):
        mangle = req.body
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.set_mangle(mangle, self.waiters)
                msgs.append(msg)
            except ValueError, message:
                RestController._LOGGER.debug('rest failetd')
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)


class Faucet(object):
    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
              ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    def __init__(self, dp, qoslib):
        super(Faucet, self).__init__()
        self.dp = dp
        self.qoslib = qoslib
        version = dp.ofproto.OFP_VERSION

        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)

        self.ofctl = self._OFCTL[version]

    # REST command template
    def rest_command(func):
        def _rest_command(*args, **kwargs):
            key, value = func(*args, **kwargs)
            switch_id = dpid_lib.dpid_to_str(args[0].dp.id)
            return {REST_SWITCHID: switch_id,
                    key: value}
        return _rest_command

    @rest_command
    def get_status(self, waiters):
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)
        status = REST_STATUS_ENABLE
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                if flow_stat['priority'] == STATUS_FLOW_PRIORITY:
                    status = REST_STATUS_DISABLE
                else:
                    status = flow_stats

        return REST_STATUS, status 


    @rest_command
    def set_mangle(self, mangle_qry, waiters):
        """"""
        properties = parse_qs(mangle_qry)
        mangle = qoslib.QoSLib.mangle(self.dp)
        RestController._LOGGER.debug('rest %s' % properties)
        for key, value in properties.iteritems():
            mangle.add_property(key, value[0])

        try:
            self.qoslib.add_mangle(mangle)
            msg = {'result': 'success', 
                'details': 'mangle added. : %s' % properties}
        except:
            RestController._LOGGER.debug('rest f1')
            msg = {'result': 'failed',
                'details': 'failed added mangle. : %s' % properties}
        
        return REST_COMMAND_RESULT, msg
   

    @rest_command
    def set_action(self, rest, waiters, vlan_id):
        msg = []
        RestController._LOGGER.debug('rest %s', rest)
        return msg


    def _to_of_flow(self, cookie, priority, match, actions):
        flow = {'cookie': cookie,
                'priority': priority,
                'flags': 0,
                'idle_timeout': 0,
                'hard_timeout': 0,
                'match': match,
                'actions': actions}
        return flow

