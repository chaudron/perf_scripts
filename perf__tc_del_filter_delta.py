#!/usr/bin/python
#
#  Copyright 2023, Eelco Chaudron
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Files name:
#    perf__tc_del_filter_delta.py
#
#  Description:
#    Simple perf script to see delta in tc_del_filter().
#
#  Author:
#    Eelco Chaudron
#
#  Notes:
#    Perf input should be as follows:
#      perf probe --del probe_ovs:*
#      perf probe -x $(which ovs-vswitchd) --add 'tc_del_filter'
#      perf probe -x $(which ovs-vswitchd) --add 'tc_del_filter%return'
#      perf record -g --call-graph dwarf -e probe_ovs:tc_del_filter -e probe_ovs:tc_del_filter__return#
#

from __future__ import print_function

import os
import sys

sys.path.append(os.environ['PERF_EXEC_PATH'] + \
    '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *

func_entry_times = {}

def probe_ovs__tc_del_filter(event_name, context, common_cpu,
                             common_secs, common_nsecs, common_pid,
                             common_comm, common_callchain, __probe_ip,
                             perf_sample_dict):

    func_entry_times[perf_sample_dict["sample"]["tid"]] = common_nsecs


def probe_ovs__tc_del_filter__return(event_name, context, common_cpu,
                                     common_secs, common_nsecs, common_pid,
                                     common_comm, common_callchain,
                                     __probe_func, __probe_ret_ip,
                                     perf_sample_dict):

    delta_time = common_nsecs - \
        func_entry_times[perf_sample_dict["sample"]["tid"]]

    print("DELAY: {:,.0f}ns in entry/return of tc_del_filter()\n".format(
        delta_time))

    for node in common_callchain:
        if 'sym' in node:
            print("\t[%x] %s" % (node['ip'], node['sym']['name']))
        else:
            print(" [%x]" % (node['ip']))

    print()

def trace_unhandled(event_name, context, event_fields_dict, perf_sample_dict):
        print(get_dict_as_string(event_fields_dict))
        print('Sample: {'+get_dict_as_string(perf_sample_dict['sample'],
                                             ', ')+'}')

def get_dict_as_string(a_dict, delimiter=' '):
    return delimiter.join(['%s=%s'%(k,str(v))for k,v in sorted(a_dict.items())])
