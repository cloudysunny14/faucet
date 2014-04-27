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

from webob import Response

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import conf_switch
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.lib import dpid as dpid_lib
from ryu.app import conf_switch_key as cs_key
from ryu.lib import mac
from ryu.base import app_manager
from ryu.exception import OFPUnknownVersion
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib.ovs import bridge
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ether
from ryu.ofproto import inet

#=============================
#          REST API
#=============================
#
# TODO:Get status api
# [class & mark]-[dscp-queue map]
#
# set a queue to the switches
# POST /qos/queue/{switch-id | all}
#
# request body format:
#  {"type": "linux-htb", "max-rate": "<int>", "queues":[
#     {"queue_name": "<string>", "max-rate": "<int>", "min-rate": "<int>", ..]}
#
# * get queue data of specific vlan group
# GET /qos/queue/{switch-id | all}/{vlan-id}
#
# set a qos to the arbitary flows
# POST /qos/{switch-id}/{vlan-id}
#
#  request body format:
#   {"match": {"<field>": "<value>", "<field2>": "<value2>"...},
#    "action": "{mark: <dscp-value>}" or {"meter": "meter-id"},
#    "queue_name": "<queue_name>"}
#
# delete a rule of the firewall switches from ruleID
# * for no vlan
# DELETE /qos/queue/{switch-id}/{queue_name}
#
# * for specific vlan group
# DELETE /qos/{switch-id}/{vlan-id}
#
# POST /qos/meter/{switch-id}
#   request body format:
#    {"meter_id": <int>,
#     "bands":[{"action": "DROP or REMARK",
#               "flag": "KBPS | PKTPS | BURST | STATS"
#               "burst_size": <int>,
#               "rate": <int>,
#               "prec_level": <int>}..]}
#
# DELETE /qos/meter/{switch

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

QOS_TABLE_ID = 0

REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_COMMAND_RESULT = 'command_result'
REST_PRIORITY = 'priority'
REST_VLANID = 'vlan_id'
REST_DL_VLAN = 'dl_vlan'
REST_QUEUE_TYPE = 'type'
REST_QUEUE_MAX_RATE = 'max_rate'
REST_QUEUE_MIN_RATE = 'min_rate'
REST_QUEUES = 'queues'
REST_QUEUE_NAME = 'queue_name'
REST_QOS = 'qos'
REST_QOS_ID = 'qosid'
REST_COOKIE = 'cookie'

REST_MATCH = 'match'
REST_IN_PORT = 'in_port'
REST_SRC_MAC = 'dl_src'
REST_DST_MAC = 'dl_dst'
REST_DL_TYPE = 'dl_type'
REST_DL_TYPE_ARP = 'ARP'
REST_DL_TYPE_IPV4 = 'IPv4'
REST_DL_TYPE_IPV6 = 'IPv6'
REST_DL_VLAN = 'dl_vlan'
REST_SRC_IP = 'nw_src'
REST_DST_IP = 'nw_dst'
REST_SRC_IPV6 = 'ipv6_src'
REST_DST_IPV6 = 'ipv6_dst'
REST_NW_PROTO = 'nw_proto'
REST_NW_PROTO_TCP = 'TCP'
REST_NW_PROTO_UDP = 'UDP'
REST_NW_PROTO_ICMP = 'ICMP'
REST_NW_PROTO_ICMPV6 = 'ICMPv6'
REST_TP_SRC = 'tp_src'
REST_TP_DST = 'tp_dst'
REST_DSCP = 'ip_dscp'

REST_ACTION = 'action'
REST_ACTION_MARK = 'mark'
REST_ACTION_METER = 'meter'

REST_METER_ID = 'meter_id'
REST_METER_BURST_SIZE = 'burst_size'
REST_METER_RATE = 'rate'
REST_METER_PREC_LEVEL = 'prec_level'
REST_METER_BANDS = 'bands'
REST_METER_ACTION_DROP = 'drop'
REST_METER_ACTION_REMARK = 'remark'

STATUS_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX
QOS_PRIORITY_MAX = ofproto_v1_3_parser.UINT16_MAX - 1
QOS_PRIORITY_MIN = 0

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094
COOKIE_SHIFT_VLANID = 32

LOG = logging.getLogger(__name__)


class RestQoSAPI(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'conf_switch': conf_switch.ConfSwitchSet,
        'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestQoSAPI, self).__init__(*args, **kwargs)

        # logger configure
        QoSController.set_logger(self.logger)
        self.cs = kwargs['conf_switch']
        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters

        mapper = wsgi.mapper
        wsgi.registory['QoSController'] = self.data
        path = '/qos'
        requirements = {'switchid': SWITCHID_PATTERN,
                        'vlanid': VLANID_PATTERN}

        # for firewall status
        uri = path + '/queue/status/{switchid}'
        mapper.connect('qos', uri,
                       controller=QoSController, action='get_status',
                       conditions=dict(method=['GET']))

        # for no VLAN data
        uri = path + '/queue/{switchid}'
        mapper.connect('qos', uri,
                       controller=QoSController, action='get_queue',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        mapper.connect('qos', uri,
                       controller=QoSController, action='set_queue',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        mapper.connect('qos', uri,
                       controller=QoSController, action='delete_queue',
                       conditions=dict(method=['DELETE']),
                       requirements=requirements)

        # for no VLAN data
        uri = path + '/{switchid}'
        mapper.connect('qos', uri, controller=QoSController,
                       action='get_qos',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        mapper.connect('qos', uri, controller=QoSController,
                       action='set_qos',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        mapper.connect('qos', uri, controller=QoSController,
                       action='delete_qos',
                       conditions=dict(method=['DELETE']),
                       requirements=requirements)

        # for VLAN data
        uri += '/{vlanid}'
        mapper.connect('qos', uri, controller=QoSController,
                       action='get_vlan_qos',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        mapper.connect('qos', uri, controller=QoSController,
                       action='set_vlan_qos',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        mapper.connect('qos', uri, controller=QoSController,
                       action='delete_vlan_qos',
                       conditions=dict(method=['DELETE']),
                       requirements=requirements)

        # for no VLAN data
        uri = path + '/meter/{switchid}'
        mapper.connect('qos', uri, controller=QoSController,
                       action='get_meter',
                       conditions=dict(method=['GET']),
                       requirements=requirements)

        mapper.connect('qos', uri, controller=QoSController,
                       action='set_meter',
                       conditions=dict(method=['POST']),
                       requirements=requirements)

        mapper.connect('qos', uri, controller=QoSController,
                       action='delete_meter',
                       conditions=dict(method=['DELETE']),
                       requirements=requirements)


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

    @set_ev_cls(conf_switch.EventConfSwitchSet)
    def conf_switch_set_handler(self, ev):
        self.logger.debug("conf_switch set: %s", ev)
        if ev.key == cs_key.OVSDB_ADDR:
            QoSController.set_ovsdb_addr(ev.dpid, ev.value)
        else:
            self.logger.debug("unknown event: %s", ev)

    @set_ev_cls(conf_switch.EventConfSwitchDel)
    def conf_switch_del_handler(self, ev):
        self.logger.debug("conf_switch del: %s", ev)
        if ev.key == cs_key.OVSDB_ADDR:
            QoSController.delete_ovsdb_addr(ev.dpid)
        else:
            self.logger.debug("unknown event: %s", ev)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            QoSController.regist_ofs(ev.dp, self.CONF)
        else:
            QoSController.unregist_ofs(ev.dp)

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2 or later
    @set_ev_cls(ofp_event.EventOFPQueueStatsReply, MAIN_DISPATCHER)
    def queue_stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)


class QoSOfsList(dict):
    def __init__(self):
        super(QoSOfsList, self).__init__()

    def get_ofs(self, dp_id):
        if len(self) == 0:
            raise ValueError('qos sw is not connected.')

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
                msg = 'qos sw is not connected. : switchID=%s' % dp_id
                raise ValueError(msg)

        return dps


class QoSController(ControllerBase):
    """"""

    _OFS_LIST = QoSOfsList()
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(QoSController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[QoS][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @staticmethod
    def regist_ofs(dp, CONF):
        if dp.id in QoSController._OFS_LIST:
            return

        dpid_str = dpid_lib.dpid_to_str(dp.id)
        try:
            f_ofs = QoS(dp, CONF)
            f_ofs.set_default_flow()
        except OFPUnknownVersion, message:
            QoSController._LOGGER.info('dpid=%s: %s',
                                        dpid_str, message)
            return

        QoSController._OFS_LIST.setdefault(dp.id, f_ofs)
        QoSController._LOGGER.info('dpid=%s: Join qos switch.',
                                    dpid_str)

    @staticmethod
    def unregist_ofs(dp):
        if dp.id in QoSController._OFS_LIST:
            del QoSController._OFS_LIST[dp.id]
            QoSController._LOGGER.info('dpid=%s: Leave qos switch.',
                                            dpid_lib.dpid_to_str(dp.id))

    @staticmethod
    def set_ovsdb_addr(dpid, value):
        ofs = QoSController._OFS_LIST.get(dpid, None)
        if ofs is not None:
            ofs.set_ovsdb_addr(dpid, value)

    @staticmethod
    def delete_ovsdb_addr(dpid):
        ofs = QoSController._OFS_LIST.get(dpid, None)
        ofs.set_ovsdb_addr(dpid, None)

    # GET /qos/queue/{switchid}
    def get_queue(self, req, switchid, **_kwargs):
        return self._get_queue(switchid, 'get_queue')

    # POST /qos/queue/{switchid}
    def set_queue(self, req, switchid, **_kwargs):
        return self._set_queue(req, switchid, 'set_queue')

    # DELETE /qos/queue/{switchid}
    def delete_queue(self, req, switchid, **_kwargs):
        return self._delete_queue(req, switchid, 'delete_queue')

    def _delete_queue(self, req, switchid, vlan_id=VLANID_NONE):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.delete_queue(None, self.waiters)
                msgs.append(msg)
            except ValueError, message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)


    # GET /qos/queue/status
    def get_status(self, req, switchid, **_kwargs):
        return self._access_switch(switchid,
                                   waiters=self.waiters)

    def _access_switch(self, switchid, waiters):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            status = f_ofs.get_queue_status(waiters)
            msgs.append(status)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)


    def _get_queue(self, switchid, vlan_id=VLANID_NONE):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            queue = f_ofs.get_queue()
            msgs.append(queue)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    def _set_queue(self, req, switchid, vlan_id=VLANID_NONE):
        try:
            queue = eval(req.body)
        except SyntaxError:
            QoSController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.set_queue(queue, self.waiters)
                msgs.append(msg)
            except ValueError, message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)


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

    # GET /qos/{switchid}
    def get_qos(self, req, switchid, **_kwargs):
        return self._get_qos(switchid)

    # GET /qos/{switchid}/{vlanid}
    def get_vlan_qos(self, req, switchid, vlanid, **_kwargs):
        return self._get_qos(switchid, vlan_id=vlanid)

    # POST /qos/{switchid}
    def set_qos(self, req, switchid, **_kwargs):
        return self._set_qos(req, switchid)

    # POST /qos/{switchid}/{vlanid}
    def set_vlan_qos(self, req, switchid, vlanid, **_kwargs):
        return self._set_qos(req, switchid, vlan_id=vlanid)

    # DELETE /qos/{switchid}
    def delete_qos(self, req, switchid, **_kwargs):
        return self._delete_rule(req, switchid)

    # DELETE /qos/{switchid}/{vlanid}
    def delete_vlan_qos(self, req, switchid, vlanid, **_kwargs):
        return self._delete_rule(req, switchid, vlan_id=vlanid)

    def _get_qos(self, switchid, vlan_id=VLANID_NONE):
        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = QoSController._conv_toint_vlanid(vlan_id)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            rules = f_ofs.get_qos(self.waiters, vid)
            msgs.append(rules)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    def _set_qos(self, req, switchid, vlan_id=VLANID_NONE):
        try:
            rule = eval(req.body)
        except SyntaxError:
            QoSController._LOGGER.debug('invalid syntaxs %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = QoSController._conv_toint_vlanid(vlan_id)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.set_qos(rule, self.waiters, vid)
                msgs.append(msg)
            except ValueError, message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    def _delete_qos(self, req, switchid, vlan_id=VLANID_NONE):
        try:
            ruleid = eval(req.body)
        except SyntaxError:
            QoSController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
            vid = QoSController._conv_toint_vlanid(vlan_id)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.delete_qos(ruleid, self.waiters, vid)
                msgs.append(msg)
            except ValueError, message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # GET /meter/{switchid}
    def get_meter(self, req, switchid, **_kwargs):
        return self._get_meter(switchid)

    # POST /qos/{switchid}
    def set_meter(self, req, switchid, **_kwargs):
        return self._set_meter(req, switchid)

    # DELETE /qos/{switchid}
    def delete_meter(self, req, switchid, **_kwargs):
        return self._delete_meter(req, switchid)

    def _set_meter(self, req, switchid):
        try:
            meter = eval(req.body)
        except SyntaxError:
            QoSController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self._OFS_LIST.get_ofs(switchid)
        except ValueError, message:
            return Response(status=400, body=str(message))

        msgs = []
        for f_ofs in dps.values():
            try:
                msg = f_ofs.set_meter(meter, self.waiters)
                msgs.append(msg)
            except ValueError, message:
                return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)


    @staticmethod
    def _conv_toint_vlanid(vlan_id):
        if vlan_id != REST_ALL:
            vlan_id = int(vlan_id)
            if (vlan_id != VLANID_NONE and
                    (vlan_id < VLANID_MIN or VLANID_MAX < vlan_id)):
                msg = 'Invalid {vlan_id} value. Set [%d-%d]' % (VLANID_MIN,
                                                                VLANID_MAX)
                raise ValueError(msg)
        return vlan_id


class QoS(object):

    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
              ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    def __init__(self, dp, CONF):
        super(QoS, self).__init__()
        self.vlan_list = {}
        self.vlan_list[VLANID_NONE] = 0  # for VLAN=None
        self.dp = dp
        self.version = dp.ofproto.OFP_VERSION
        self.queue_list = {}
        self.CONF = CONF
        self.ovsdb_addr = None
        self.ovs_bridge = None

        if self.version not in self._OFCTL:
            raise OFPUnknownVersion(version=self.version)

        self.ofctl = self._OFCTL[self.version]

    def set_default_flow(self):
        if self.version == ofproto_v1_0.OFP_VERSION:
            return

        cookie = 0
        priority = QOS_PRIORITY_MIN
        actions = [{'type': 'GOTO_TABLE',
                    'table_id': QOS_TABLE_ID+1}]
        flow = self._to_of_flow(cookie=cookie,
                                priority=priority,
                                match={},
                                actions=actions)

        cmd = self.dp.ofproto.OFPFC_ADD
        self.ofctl.mod_flow_entry(self.dp, flow, cmd)

    def set_ovsdb_addr(self, dpid, ovsdb_addr):
        # easy check if the address format valid
        _proto, _host, _port = ovsdb_addr.split(':')

        old_address = self.ovsdb_addr
        if old_address == ovsdb_addr:
            return
        if ovsdb_addr is None:
            if self.ovs_bridge:
                self.ovs_bridge.del_controller()
                self.ovs_bridge = None
            return
        self.ovsdb_addr = ovsdb_addr
        if self.ovs_bridge is None:
            ovs_bridge = bridge.OVSBridge(self.CONF, dpid, ovsdb_addr)
            self.ovs_bridge = ovs_bridge
            ovs_bridge.init()

    def _update_vlan_list(self, vlan_list):
        for vlan_id in self.vlan_list.keys():
            if vlan_id is not VLANID_NONE and vlan_id not in vlan_list:
                del self.vlan_list[vlan_id]

    def _get_cookie(self, vlan_id):
        if vlan_id == REST_ALL:
            vlan_ids = self.vlan_list.keys()
        else:
            vlan_ids = [vlan_id]

        cookie_list = []
        for vlan_id in vlan_ids:
            self.vlan_list.setdefault(vlan_id, 0)
            self.vlan_list[vlan_id] += 1
            self.vlan_list[vlan_id] &= ofproto_v1_3_parser.UINT32_MAX
            cookie = (vlan_id << COOKIE_SHIFT_VLANID) + \
                self.vlan_list[vlan_id]
            cookie_list.append([cookie, vlan_id])

        return cookie_list

    @staticmethod
    def _cookie_to_qosid(cookie):
        return cookie & ofproto_v1_3_parser.UINT32_MAX

    # REST command template
    def rest_command(func):
        def _rest_command(*args, **kwargs):
            key, value = func(*args, **kwargs)
            switch_id = dpid_lib.dpid_to_str(args[0].dp.id)
            return {REST_SWITCHID: switch_id,
                    key: value}
        return _rest_command


    @rest_command
    def get_queue_status(self, waiters):
        msgs = self.ofctl.get_queue_stats(self.dp, waiters)
        return REST_COMMAND_RESULT, msgs


    @rest_command
    def get_queue(self):
        if len(self.queue_list):
            msg = {'result': 'success',
                   'details': self.queue_list}
        else:
            msg = {'result': 'failure',
                   'details': 'Queue is not exists.'}

        return REST_COMMAND_RESULT, msg

    @rest_command
    def set_queue(self, rest, waiters):
        self.queue_list.clear()
        queue_type = rest.get(REST_QUEUE_TYPE, 'linux-htb')
        parent_max_rate = rest.get(REST_QUEUE_MAX_RATE, None)
        queues = rest.get(REST_QUEUES, [])
        queue_id = 0
        queue_config = []
        for queue in queues:
            queue_name = queue.get(REST_QUEUE_NAME, None)
            if queue_name is None:
                raise ValueError('Required to set the name of queue')
            max_rate = queue.get(REST_QUEUE_MAX_RATE, None)
            config = {}
            if max_rate is not None:
                config['max-rate'] = max_rate
            min_rate = queue.get(REST_QUEUE_MIN_RATE, None)
            if min_rate is not None:
                config['min-rate'] = min_rate
            if len(config):
                queue_config.append(config)
            self.queue_list[queue_name] = \
                {'queue_id': queue_id,
                 'config': config}
            queue_id += 1

        if self.ovs_bridge is None:
            msg = {'result': 'success',
                   'details': 'Success added but actually not woking. \
                    plese set ovsaddr via ..'}
        else:
            vif_ports = self.ovs_bridge.get_external_ports()
            res_list = []
            for port in vif_ports:
                res = self.ovs_bridge.set_qos(port.port_name, type=queue_type,
                                       max_rate=parent_max_rate,
                                       queues=queue_config)
                if len(res) == len(queue_config) + 1:
                     res_list.append(queue_config)

            if len(res_list):
                msg = {'result': 'success',
                       'details': self.queue_list}
            else:
                msg = {'result': 'failure',
                   'details': 'Invalid queue configuration.'}

        return REST_COMMAND_RESULT, msg

    def _delete_queue(self):
        vif_ports = self.ovs_bridge.get_external_ports()
        for port in vif_ports:
            self.ovs_bridge.del_qos(port.port_name)

    @rest_command
    def delete_queue(self, rest, waiters):
        self.queue_list.clear()
        self._delete_queue()
        msg = 'success'
        return REST_COMMAND_RESULT, msg

    @rest_command
    def set_qos(self, rest, waiters, vlan_id):
        msgs = []
        cookie_list = self._get_cookie(vlan_id)
        for cookie, vid in cookie_list:
            msg = self._set_qos(cookie, rest, waiters, vid)
            msgs.append(msg)
        return REST_COMMAND_RESULT, msgs

    def _set_qos(self, cookie, rest, waiters, vlan_id):
        priority = int(rest.get(REST_PRIORITY, QOS_PRIORITY_MIN))

        if (QOS_PRIORITY_MAX < priority):
            raise ValueError('Invalid priority value. Set [%d-%d]'
                             % (QOS_PRIORITY_MIN, QOS_PRIORITY_MAX))

        match_value = rest[REST_MATCH]

        if vlan_id:
            match_value[REST_DL_VLAN] = vlan_id

        match = Match.to_openflow(match_value)

        queue_name = rest.get(REST_QUEUE_NAME, None)
        if queue_name is None:
            raise ValueError('Required to set the name of queue')

        actions = []
        queue = self.queue_list.get(queue_name, None)
        if queue is None:
            raise ValueError('Queue name is not exists.')

        actions.append({'type': 'SET_QUEUE',
                        'queue_id': queue['queue_id']})

        action = rest.get(REST_ACTION, None)
        if action is not None:
            if REST_ACTION_MARK in action:
                actions.append({'type': 'SET_FIELD',
                  'field': REST_DSCP,
                  'value': int(action[REST_ACTION_MARK])})
            elif REST_ACTION_METER in action:
                actions.append({'type': 'METER',
                                'meter_id': action[REST_ACTION_METER]})

        actions.append({'type': 'GOTO_TABLE',
                        'table_id': QOS_TABLE_ID + 1})
        flow = self._to_of_flow(cookie=cookie, priority=priority,
                                match=match, actions=actions)

        QoSController._LOGGER.debug('invalid syntax %s', flow)

        cmd = self.dp.ofproto.OFPFC_ADD
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        qos_id = QoS._cookie_to_qosid(cookie)
        msg = {'result': 'success',
               'details': 'QoS added. : qos_id=%d' % qos_id}

        if vlan_id != VLANID_NONE:
            msg.setdefault(REST_VLANID, vlan_id)
        return msg

    @rest_command
    def get_qos(self, waiters, vlan_id):
        rules = {}
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)

        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                priority = flow_stat[REST_PRIORITY]
                if priority != STATUS_FLOW_PRIORITY:
                    vid = flow_stat[REST_MATCH].get(REST_DL_VLAN, VLANID_NONE)
                    if vlan_id == REST_ALL or vlan_id == vid:
                        rule = self._to_rest_rule(flow_stat)
                        rules.setdefault(vid, [])
                        rules[vid].append(rule)

        get_data = []
        for vid, rule in rules.items():
            if vid == VLANID_NONE:
                vid_data = {REST_QOS: rule}
            else:
                vid_data = {REST_VLANID: vid, REST_QOS: rule}
            get_data.append(vid_data)

        return get_data

    @rest_command
    def delete_qos(self, rest, waiters, vlan_id):
        try:
            if rest[REST_QOS_ID] == REST_ALL:
                rule_id = REST_ALL
            else:
                rule_id = int(rest[REST_QOS_ID])
        except:
            raise ValueError('Invalid ruleID.')

        vlan_list = []
        delete_list = []

        msgs = self.ofctl.get_flow_stats(self.dp, waiters)
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                cookie = flow_stat[REST_COOKIE]
                ruleid = QoS._cookie_to_ruleid(cookie)
                priority = flow_stat[REST_PRIORITY]
                dl_vlan = flow_stat[REST_MATCH].get(REST_DL_VLAN, VLANID_NONE)

                if priority != STATUS_FLOW_PRIORITY:
                    if ((rule_id == REST_ALL or rule_id == ruleid) and
                            (vlan_id == dl_vlan or vlan_id == REST_ALL)):
                        match = Match.to_mod_openflow(flow_stat[REST_MATCH])
                        delete_list.append([cookie, priority, match])
                    else:
                        if dl_vlan not in vlan_list:
                            vlan_list.append(dl_vlan)

        self._update_vlan_list(vlan_list)

        if len(delete_list) == 0:
            msg_details = 'Rule is not exist.'
            if rule_id != REST_ALL:
                msg_details += ' : ruleID=%d' % rule_id
            msg = {'result': 'failure',
                   'details': msg_details}
        else:
            cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
            actions = []
            delete_ids = {}
            for cookie, priority, match in delete_list:
                flow = self._to_of_flow(cookie=cookie, priority=priority,
                                        match=match, actions=actions)
                self.ofctl.mod_flow_entry(self.dp, flow, cmd)

                vid = match.get(REST_DL_VLAN, VLANID_NONE)
                rule_id = QoS._cookie_to_qosid(cookie)
                delete_ids.setdefault(vid, '')
                delete_ids[vid] += (('%d' if delete_ids[vid] == ''
                                     else ',%d') % rule_id)

            msg = []
            for vid, rule_ids in delete_ids.items():
                del_msg = {'result': 'success',
                           'details': 'Rule deleted. : ruleID=%s' % rule_ids}
                if vid != VLANID_NONE:
                    del_msg.setdefault(REST_VLANID, vid)
                msg.append(del_msg)

        return REST_COMMAND_RESULT, msg

    @rest_command
    def set_meter(self, rest, waiters):
        msgs = []
        msg = self._set_meter(rest, waiters)
        msgs.append(msg)
        return REST_COMMAND_RESULT, msgs

    def _set_meter(self, rest, waiters):
        cmd = self.dp.ofproto.OFPMC_ADD
        try:
            self.ofctl.mod_meter_entry(self.dp, rest, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        msg = {'result': 'success',
               'details': 'Meter added. : meter_id=%s' %
                 rest[REST_METER_ID]}
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

    def _to_rest_rule(self, flow):
        ruleid = QoS._cookie_to_qosid(flow[REST_COOKIE])
        rule = {REST_QOS_ID: ruleid}
        rule.update({REST_PRIORITY: flow[REST_PRIORITY]})
        rule.update(Match.to_rest(flow))
        return rule

class Match(object):

    _CONVERT = {REST_DL_TYPE:
                {REST_DL_TYPE_ARP: ether.ETH_TYPE_ARP,
                 REST_DL_TYPE_IPV4: ether.ETH_TYPE_IP,
                 REST_DL_TYPE_IPV6: ether.ETH_TYPE_IPV6},
                REST_NW_PROTO:
                {REST_NW_PROTO_TCP: inet.IPPROTO_TCP,
                 REST_NW_PROTO_UDP: inet.IPPROTO_UDP,
                 REST_NW_PROTO_ICMP: inet.IPPROTO_ICMP,
                 REST_NW_PROTO_ICMPV6: inet.IPPROTO_ICMPV6}}

    @staticmethod
    def to_openflow(rest):

        def __inv_combi(msg):
            raise ValueError('Invalid combination: [%s]' % msg)

        def __inv_2and1(*args):
            __inv_combi('%s=%s and %s' % (args[0], args[1], args[2]))

        def __inv_2and2(*args):
            __inv_combi('%s=%s and %s=%s' % (
                args[0], args[1], args[2], args[3]))

        def __inv_1and1(*args):
            __inv_combi('%s and %s' % (args[0], args[1]))

        def __inv_1and2(*args):
            __inv_combi('%s and %s=%s' % (args[0], args[1], args[2]))

        match = {}

        # error check
        dl_type = rest.get(REST_DL_TYPE)
        nw_proto = rest.get(REST_NW_PROTO)
        if dl_type is not None:
            if dl_type == REST_DL_TYPE_ARP:
                if REST_SRC_IPV6 in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_ARP, REST_SRC_IPV6)
                if REST_DST_IPV6 in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_ARP, REST_DST_IPV6)
                if nw_proto:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_ARP, REST_NW_PROTO)
            elif dl_type == REST_DL_TYPE_IPV4:
                if REST_SRC_IPV6 in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_IPV4, REST_SRC_IPV6)
                if REST_DST_IPV6 in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_IPV4, REST_DST_IPV6)
                if nw_proto == REST_NW_PROTO_ICMPV6:
                    __inv_2and2(
                        REST_DL_TYPE, REST_DL_TYPE_IPV4,
                        REST_NW_PROTO, REST_NW_PROTO_ICMPV6)
            elif dl_type == REST_DL_TYPE_IPV6:
                if REST_SRC_IP in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_IPV6, REST_SRC_IP)
                if REST_DST_IP in rest:
                    __inv_2and1(
                        REST_DL_TYPE, REST_DL_TYPE_IPV6, REST_DST_IP)
                if nw_proto == REST_NW_PROTO_ICMP:
                    __inv_2and2(
                        REST_DL_TYPE, REST_DL_TYPE_IPV6,
                        REST_NW_PROTO, REST_NW_PROTO_ICMP)
            else:
                raise ValueError('Unknown dl_type : %s' % dl_type)
        else:
            if REST_SRC_IP in rest:
                if REST_SRC_IPV6 in rest:
                    __inv_1and1(REST_SRC_IP, REST_SRC_IPV6)
                if REST_DST_IPV6 in rest:
                    __inv_1and1(REST_SRC_IP, REST_DST_IPV6)
                if nw_proto == REST_NW_PROTO_ICMPV6:
                    __inv_1and2(
                        REST_SRC_IP, REST_NW_PROTO, REST_NW_PROTO_ICMPV6)
                rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
            elif REST_DST_IP in rest:
                if REST_SRC_IPV6 in rest:
                    __inv_1and1(REST_DST_IP, REST_SRC_IPV6)
                if REST_DST_IPV6 in rest:
                    __inv_1and1(REST_DST_IP, REST_DST_IPV6)
                if nw_proto == REST_NW_PROTO_ICMPV6:
                    __inv_1and2(
                        REST_DST_IP, REST_NW_PROTO, REST_NW_PROTO_ICMPV6)
                rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
            elif REST_SRC_IPV6 in rest:
                if nw_proto == REST_NW_PROTO_ICMP:
                    __inv_1and2(
                        REST_SRC_IPV6, REST_NW_PROTO, REST_NW_PROTO_ICMP)
                rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
            elif REST_DST_IPV6 in rest:
                if nw_proto == REST_NW_PROTO_ICMP:
                    __inv_1and2(
                        REST_DST_IPV6, REST_NW_PROTO, REST_NW_PROTO_ICMP)
                rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
            else:
                if nw_proto == REST_NW_PROTO_ICMP:
                    rest[REST_DL_TYPE] = REST_DL_TYPE_IPV4
                elif nw_proto == REST_NW_PROTO_ICMPV6:
                    rest[REST_DL_TYPE] = REST_DL_TYPE_IPV6
                elif nw_proto == REST_NW_PROTO_TCP or \
                        nw_proto == REST_NW_PROTO_UDP:
                    raise ValueError('no dl_type was specified')
                else:
                    raise ValueError('Unknown nw_proto: %s' % nw_proto)

        for key, value in rest.items():
            if key in Match._CONVERT:
                if value in Match._CONVERT[key]:
                    match.setdefault(key, Match._CONVERT[key][value])
                else:
                    raise ValueError('Invalid rule parameter. : key=%s' % key)
            else:
                match.setdefault(key, value)

        return match

    @staticmethod
    def to_rest(openflow):
        of_match = openflow[REST_MATCH]

        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'
        ipv6_dontcare = '::'

        match = {}
        for key, value in of_match.items():
            if key == REST_SRC_MAC or key == REST_DST_MAC:
                if value == mac_dontcare:
                    continue
            elif key == REST_SRC_IP or key == REST_DST_IP:
                if value == ip_dontcare:
                    continue
            elif key == REST_SRC_IPV6 or key == REST_DST_IPV6:
                if value == ipv6_dontcare:
                    continue
            elif value == 0:
                continue

            if key in Match._CONVERT:
                conv = Match._CONVERT[key]
                conv = dict((value, key) for key, value in conv.items())
                match.setdefault(key, conv[value])
            else:
                match.setdefault(key, value)

        return match

    @staticmethod
    def to_mod_openflow(of_match):
        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'
        ipv6_dontcare = '::'

        match = {}
        for key, value in of_match.items():
            if key == REST_SRC_MAC or key == REST_DST_MAC:
                if value == mac_dontcare:
                    continue
            elif key == REST_SRC_IP or key == REST_DST_IP:
                if value == ip_dontcare:
                    continue
            elif key == REST_SRC_IPV6 or key == REST_DST_IPV6:
                if value == ipv6_dontcare:
                    continue
            elif value == 0:
                continue

            match.setdefault(key, value)

        return match

