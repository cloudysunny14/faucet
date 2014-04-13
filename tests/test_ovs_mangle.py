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

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.lib import hub
from ryu.lib.ovs import bridge
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from lib import qoslib

LOG = logging.getLogger(__name__)
LOG_TEST_FINISH = 'TEST_FINISHED: Tests=[%s] (OK=%s NG=%s SKIP=%s)'

OVSDB_ADDR = 'tcp:127.0.0.1:6632'

class OFMangleTester(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    _CONTEXTS = {'dpset': dpset.DPSet,
                 'qoslib': qoslib.QoSLib}

    _OFCTL = {ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
              ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
              ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

    def __init__(self, *args, **kwargs):
        super(OFMangleTester, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        self.qoslib = kwargs['qoslib']
        self.qoslib.use_switch_flow = False 
        self.waiters = {}
        self.pending = []
        self.results = {}
        for t in dir(self):
            if t.startswith("test_"):
                self.pending.append(t)
        self.pending.sort(reverse=True)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        # Target switch datapath
        self.dp = ev.dp
        version = self.dp.ofproto.OFP_VERSION
        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)
        self.ofctl = self._OFCTL[version]
        hub.spawn(self._do_test)

    def test_queue_setup(self):
        self.ovsctl = bridge.OVSBridge(self.dp.id, OVSDB_ADDR)
        queue = qoslib.QoSLib.queue_tree(self.ovsctl, self.dp)
        queue.queue('high-priority', '500', '500')
        self.qoslib.register_queue(queue)
        queue = qoslib.QoSLib.queue_tree(self.ovsctl, self.dp)
        queue.queue('high-priority', '700', '700')
        self.qoslib.register_queue(queue)
        queue = qoslib.QoSLib.queue_tree(self.ovsctl, self.dp)
        queue.queue('best-effort', '10000', '10000')


    def _print_results(self):
        LOG.info("TEST_RESULTS:")
        ok = 0
        ng = 0
        skip = 0
        for t in sorted(self.results.keys()):
            if self.results[t] is True:
                ok += 1
            else:
                ng += 1
            LOG.info("    %s: %s", t, self.results[t])
        LOG.info(LOG_TEST_FINISH, len(self.pending), ok, ng, skip)

    def _do_test(self):
        """"""
        for test in self.pending:
            self.results[test] = getattr(self, test)()
        self._print_results()
