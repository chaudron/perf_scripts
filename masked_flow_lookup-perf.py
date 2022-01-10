#!/usr/bin/python
#
#  Copyright 2020, Eelco Chaudron
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
#    masked_flow_lookup-perf.py
#
#  Description:
#    Simple script to analyze masked_flow_lookup events, and gather some
#    statistics based on the backtrace.
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    10 June 2020
#
#  Usage:
#    perf script -s masked_flow_lookup <list of functions to stop bt processing>
#
#  Example:
#    First add the probe for the function call and take some samples:
#      perf probe --module=openvswitch --add masked_flow_lookup
#      perf record -e probe:masked_flow_lookup -s --call-graph dwarf -g -i -a
#
#    Now you can load the tool trough the script command
#      perf script -s masked_flow_lookup-perf.py __do_softirq,__softirqentry_text_start,udp_sendmsg,tcp_sendmsg,tcp_write_xmit
#


#
# Global imports
#
import ast
import os
import sys
from natsort import natsorted


#
# Perf specific imports
#
sys.path.append(os.environ['PERF_EXEC_PATH'] +
                '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')


from Core import *
from perf_trace_context import *


#
# Global variables
#
all_backtraces = autodict()


#
# Extract summary backtrace from full backtrace
#
def get_bt_kernel(callchain):
    bin_callchain = list()
    for node in callchain:
        #
        # The function below also does a strarts with /lib/modules/.." as the
        # first time a function from a kernel mod is used it's displayed this
        # way, i.e. "/lib/modules/3.10.0-1127.10.1.el7.x86_64/kernel/net/openvswitch/openvswitch.ko.xz"
        #
        if 'sym' in node and 'dso' in node and \
           (node['dso'] == "[kernel.kallsyms]" or
            node['dso'].startswith("/lib/modules/")):
            bin_callchain.append(node['sym']['name'])

            if node['sym']['name'] in stop_at_functions:
                break

    return bin_callchain


#
# Beginning of the trace
#
def trace_begin():
    print("- Start processing records...")


#
# End of the trace, show results
#
def trace_end():
    bts = 0

    print("- All records processed!")
    print("- Global callback events...")
    for bt, bt_val in sorted(all_backtraces.iteritems(),
                             key=lambda(k, v): (v, k)):
        bts += 1

        print("  * Sequence[{}] repeated {} times globally".
              format(bts, bt_val['count']))

        for cpu, count in natsorted(bt_val.items()):
            if not cpu.startswith("CPU"):
                continue

            print("    Sequence[{}] repeated {} times on {}".format(
                bts, count, cpu))

        print("    Backtrace:")
        bt_list = ast.literal_eval(bt)
        for i, bt_entry in enumerate(bt_list):
            print("      #{:<2} {}  ".format(i, bt_entry))

        print("")


def probe__masked_flow_lookup(event_name, context, common_cpu,
                              common_secs, common_nsecs, common_pid,
                              common_comm, common_callchain, __probe_ip,
                              perf_sample_dict):

    bt = get_bt_kernel(common_callchain)

    try:
        all_backtraces[str(bt)]['count'] += 1
    except TypeError:
        all_backtraces[str(bt)]['count'] = 1

    try:
        all_backtraces[str(bt)]['CPU' + str(common_cpu)] += 1
    except TypeError:
        all_backtraces[str(bt)]['CPU' + str(common_cpu)] = 1


#
# Handle command line argument
#
if len(sys.argv) >= 2:
    stop_at_functions = sys.argv[1].split(",")
else:
    stop_at_functions = list()
