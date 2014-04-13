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

import cmd
import sys, getopt
import rest_client

BANNER = \
"""
  __                      _   
 / _| __ _ _   _  ___ ___| |_ 
| |_ / _` | | | |/ __/ _ \ __|
|  _| (_| | |_| | (_|  __/ |_ 
|_|  \__,_|\__,_|\___\___|\__|
                              
"""

def command(login_required=True):
    """a decorator for handling authentication and exceptions"""
    def decorate(f):
        def wrapper(self, args):
            if login_required and self.api_client is None:
                self.stdout.write("Please 'login' to execute this command\n")
                return

            try:
                return f(self, str(args))
            except TypeError, e:
                self.stdout.write(str(e) + '\n')
            except rest_client.ErrorResponse, e:
                msg = e.user_error_msg or str(e)
                self.stdout.write('Error: %s\n' % msg)

        wrapper.__doc__ = f.__doc__
        return wrapper
    return decorate


class MangleTerm(cmd.Cmd):
    def __init__(self, switch_id, api_client):
        cmd.Cmd.__init__(self)
        self._switch_id = switch_id
        self.api_client = api_client

    def emptyline(self):
        None

    @command()
    def do_action(self, action):
        resp = self.api_client.set_action(action,
            self._switch_id)       
        print resp 

    def do_queue(self, s):
        term = QueueTerm()
        term.prompt = self.prompt[:-2]+':queue> '
        term.cmdloop()

    def do_exit(self, s):
        return True


class QueueTerm(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)

    def emptyline(self):
        None

    def do_exit(self, s):
        return True


class IpTerm(cmd.Cmd):
    def __init__(self, switch_id, api_client):
        cmd.Cmd.__init__(self)
        self._switch_id = switch_id
        self._api_client = api_client

    def emptyline(self):
        None

    def do_route(self, route):
        resp = self._api_client.set_route(route,
            self._switch_id)
        print resp

    def do_exit(self, s):
        return True


class FaucetTerm(cmd.Cmd):

    def __init__(self, host):
        cmd.Cmd.__init__(self)
        self.intro = BANNER 
        self.prompt = '(%s)faucet> ' % (host)
        self.api_client = None
        try:
            self.api_client = rest_client.FaucetClient(host)
        except IOError:
            pass # don't worry if it's not there

    def emptyline(self):
        None

    @command()
    def do_flow_status(self, switch=None):
        """list files in current remote directory"""
        resp = self.api_client.get_flow_status(switch)
        print resp

    @command()
    def do_queue_status(self, switch=None):
        """list queue status each switch"""
        resp = self.api_client.get_queue_status(switch)
        print resp

    def do_mangle(self, switch_id):
        if not len(switch_id):
            msg = 'Must specify target switch id'
            self.stdout.write('Error: %s\n' % msg)
            return

        term = MangleTerm(switch_id, self.api_client)
        term.prompt = self.prompt[:-2]+':mangle> '
        term.cmdloop()

    def do_ip(self, switch_id):
        if not len(switch_id):
            msg = 'Must specify target switch id'
            self.stdout.write('Error: %s\n' % msg)
            return
        term = IpTerm(switch_id, self.api_client)
        term.prompt = self.prompt[:-2]+':ip> '
        term.cmdloop()

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        sys.exit(2)
    host = '127.0.0.1:8080'
    if len(args) > 0:
        host = args[0]
    term = FaucetTerm(host)
    term.cmdloop()


if __name__ == '__main__':
    main(sys.argv[1:])
