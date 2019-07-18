#!/usr/bin/env python
# encoding: utf-8

# Remi Frenay, WorldStream B.V., 2019
# <rf@worldstream.nl>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
################################################################################

__author__ = 'Remi Frenay <rf@worldstream.nl>'
__version__ = '1.1'
__plugin_name__ = 'check_powerdns_auth.py'

import os
import pickle
import re
import subprocess
import sys
import time

# Clean area interfaces
pdns_tool = 'pdns_control'

querylist = ['udp4-queries', 'udp6-queries', 'tcp-queries']
avglist = querylist + ['udp4-answers', 'udp6-answers', 'tcp-answers', 'recursing-questions', 'recursing-answers',
                       'query-cache-hit', 'query-cache-miss', 'packetcache-hit', 'packetcache-miss']
watchlist = avglist + ['security-status']


class MStatus:
    """Monitoring status enum"""

    def __init__(self):
        self.OK = 0
        self.WARNING = 1
        self.CRITICAL = 2
        self.UNKNOWN = 3


# noinspection PyTypeChecker
def parse_args():
    # Build argument list
    try:
        import argparse
    except ImportError:
        print 'Error importing library python-argparse'
        sys.exit(MStatus().UNKNOWN)

    parser = argparse.ArgumentParser(
        prog=__plugin_name__,
        description='Icinga/Nagios plugin, interned to check PowerDNS status using pdns_control. '
                    'A non-zero exit code is generated, if the numbers of DNS queries per seconds exceeds'
                    ' warning/critical'
                    'values. Additionally the plugin checks for the security-status of PowerDNS. ',
        epilog='This program is free software: you can redistribute it and/or modify '
               'it under the terms of the GNU General Public License as published by '
               'the Free Software Foundation, either version 3 of the License, or '
               'at your option) any later version. Author: ' + __author__)
    parser.add_argument('-S', '--socket-dir', help='Where the PowerDNS controlsocket will live', type=str, default='')
    parser.add_argument('-n', '--config-name', help='Name of PowerDNS virtual configuration', type=str, default='')
    parser.add_argument('-w', '--warning', help='Warning threshold (Queries/s)', type=int, default=0)
    parser.add_argument('-c', '--critical', help='Critical threshold (Queries/s)', type=int, default=0)
    parser.add_argument('-s', '--scratch', help='Scratch / temp base directory. Must exist. (default: /tmp)', type=str,
                        default='/tmp')
    parser.add_argument('-p', '--perfdata', help='Print performance data, (default: off)', action='store_true')
    parser.add_argument('--skipsecurity', help='Skip PowerDNS security status, (default: off)', action='store_true')
    parser.add_argument('-T', '--test', help='Test case; Use fake data and do not run pdns_control',
                        action='store_true')
    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    return parser.parse_args()


class Monitoring:
    """"Monitoring"""

    def __init__(self):
        self.status = MStatus().UNKNOWN
        self.message = "Unknown Status"
        self.perfdata = []

    def set_status(self, _status):
        if _status == MStatus().UNKNOWN:
            return
        if self.status == MStatus().CRITICAL:
            return
        if _status == MStatus().CRITICAL:
            self.status = _status
            return
        if self.status == MStatus().WARNING:
            return
        self.status = _status

    def set_message(self, _message):
        self.message = _message

    def set_perfdata(self, _label, _value, _warning, _critical):
        self.perfdata.append([_label, _value, _warning, _critical])

    def report(self):
        if self.status == MStatus().OK:
            code = "OK"
        elif self.status == MStatus().WARNING:
            code = "WARNING"
        elif self.status == MStatus().CRITICAL:
            code = "CRITICAL"
        else:
            code = "UNKNOWN"
        output = code + ' - ' + self.message
        if len(self.perfdata) > 0:
            output += '|'
            for measurement in self.perfdata:
                output += (" '%s'=%d;%d;%d;0;" % (measurement[0], measurement[1], measurement[2], measurement[3]))
        print(output)
        sys.exit(self.status)


def get_fname(_path_base, _config):
    # returns cache file name
    if _config == '':
        return os.path.join(_path_base, 'monitor-pdns-auth')
    else:
        return os.path.join(_path_base, 'monitor-pdns-auth-' + _config)


def load_measurement(_filename):
    try:
        fd = open(_filename, 'rb')
        _data_old = pickle.load(fd)
        fd.close()
        return _data_old
    except IOError:
        return dict()


def save_measurement(_filename, _data_new):
    fd = open(_filename, 'wb')
    pickle.dump(_data_new, fd)
    fd.close()


def parse_pdns(_stdout):
    _new_data = dict()

    for val in _stdout.split(','):
        m = re.match(r"^([a-z0-9\-]+)=(\d+)$", val)
        if m:
            if m.group(1) in watchlist:
                _new_data[m.group(1)] = int(m.group(2))
    return _new_data


def calc_avgps(_data_old, _data_new):
    _data_avg = dict()
    _queries = 0

    try:
        elapsed = _data_new['epoch'] - _data_old['epoch']
        for _label, _value in _data_old.items():
            if (_label in _data_new) and (_label in avglist):
                delta = _data_new[_label] - _value
                _data_avg[_label] = delta / elapsed
                if delta < 0:
                    return dict(), 0
                if _label in querylist:
                    _queries += delta
        _queries /= elapsed
        return _data_avg, _queries
    except KeyError:
        return dict(), 0
    except ZeroDivisionError:
        return dict(), 0


# main
if __name__ == '__main__':

    monitor = Monitoring()

    # prepare debug / test case
    args = parse_args()

    if args.test:
        stdout = 'corrupt-packets=0,deferred-cache-inserts=0,deferred-cache-lookup=0,dnsupdate-answers=0,' \
                 'dnsupdate-changes=0,dnsupdate-queries=0,dnsupdate-refused=0,latency=0,packetcache-hit=0,' \
                 'packetcache-miss=0,packetcache-size=0,qsize-q=0,query-cache-hit=0,query-cache-miss=0,rd-queries=0,' \
                 'recursing-answers=0,recursing-questions=0,recursion-unanswered=0,security-status=1,'\
                 'servfail-packets=0,tcp-answers=0,tcp-queries=0,timedout-packets=0,udp-answers=0,udp-answers-bytes=0,'\
                 'udp-do-queries=0,udp-queries=0,udp4-answers=0,udp4-queries=0,udp6-answers=0,udp6-queries=0,'
        data_new = parse_pdns(stdout)
        data_new['epoch'] = int(time.time())

        data_old = data_new.copy()
        data_old['epoch'] -= 1

        (data_avg, queries) = calc_avgps(data_old, data_new)
    else:
        try:
            cli = [pdns_tool]
            if args.socket_dir:
                cli.append('--socket-dir=%s' % args.socket_dir)
            if args.config_name != '':
                cli.append('--config-name=%s' % args.config_name)
            cli.append('show')
            cli.append('*')

            MyOut = subprocess.Popen(cli, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, stderr = MyOut.communicate()
            if MyOut.returncode != 0:
                monitor.set_message(stdout)
                monitor.report()
        except OSError:
            monitor.set_message("Control command '%s' not found." % pdns_tool)
            monitor.report()

        # noinspection PyUnboundLocalVariable
        data_new = parse_pdns(stdout)
        data_new['epoch'] = int(time.time())

        filename = get_fname(args.scratch, args.config_name)
        data_old = load_measurement(filename)

        (data_avg, queries) = calc_avgps(data_old, data_new)
        if len(data_new) > 1:
            save_measurement(filename, data_new)

    if ('security-status' in data_new) and (args.skipsecurity == 0):
        if data_new['security-status'] == 0:
            monitor.set_status(MStatus().CRITICAL)
            security = 'NXDOMAIN or resolution failure.'
        elif data_new['security-status'] == 1:
            monitor.set_status(MStatus().OK)
            security = 'PowerDNS running.'
        elif data_new['security-status'] == 2:
            monitor.set_status(MStatus().WARNING)
            security = 'PowerDNS upgrade recommended.'
        elif data_new['security-status'] == 3:
            monitor.set_status(MStatus().CRITICAL)
            security = 'PowerDNS upgrade mandatory.'
        else:
            monitor.set_status(MStatus().CRITICAL)
            security = "PowerDNS unexpected security-status %d." % data_new['security-status']
    else:
        security = ''
    if args.warning and (queries >= args.warning):
        monitor.set_status(MStatus().WARNING)
    if args.critical and (queries >= args.critical):
        monitor.set_status(MStatus().CRITICAL)

    monitor.set_status(MStatus().OK)
    monitor.set_message("%s Queries: %d/s." % (security, queries))
    if args.perfdata:
        for label, value in sorted(data_avg.items()):
            monitor.set_perfdata(label, value, args.warning, args.critical)
    monitor.report()
