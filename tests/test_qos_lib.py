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

import unittest
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from app import qoslib

from nose.tools import *


class _Datapath(object):
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def set_xid(self, xid):
        self.xid = xid

    def id(self):
        return '1'

    def send_msg(self, msg):
        pass


class TestQosLib(unittest.TestCase):

    """ Test case for QoS lib
    """

    def setUp(self):
        self.datapath = _Datapath()
        self.qoslib = qoslib.QoSLib()
        pass

    def tearDown(self):
        pass

    @raises(qoslib.MangleAlreadyBuildError)
    def test_mangle_already_build(self):
        mangle = qoslib.QoSLib.mangle(self.datapath)
        mangle.add_property('action', 'accept').\
            add_property('dst-address', '10.0.0.2').\
            add_property('chain', 'forward')
        self.qoslib.add_mangle(mangle)
        mangle.add_property('src-address', '10.0.0.3')

    @raises(qoslib.MangleAlreadyAddedListError)
    def test_mangle_address_list_notexist(self):
        mangle = qoslib.QoSLib.mangle(self.datapath)
        mangle.address_list('second', ['10.0.0.2', '10.0.0.3'])
        mangle.address_list('first', ['10.0.1.2', '10.0.1.3'])

    @raises(qoslib.MangleBuildError)
    def test_mangle_list_not_exist(self):
        mangle = qoslib.QoSLib.mangle(self.datapath)
        mangle.address_list('first', ['10.0.1.2', '10.0.1.3'])
        mangle.add_property('action', 'accept').\
            add_property('src-address-list', 'nothing').\
            add_property('chain', 'forward')
        self.qoslib.add_mangle(mangle)

    def test_mangle_exist_list(self):
        mangle = qoslib.QoSLib.mangle(self.datapath)
        mangle.address_list('first', ['10.0.2.3', '10.0.2.4'])
        mangle.add_property('action', 'accept').\
            add_property('src-address-list', 'first').\
            add_property('chain', 'forward')
        self.qoslib.add_mangle(mangle)
    
if __name__ == '__main__':
    unittest.main()
