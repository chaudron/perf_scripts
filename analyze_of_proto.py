#!/usr/bin/python
#
#  Copyright 2021, Eelco Chaudron
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
#    analyze_of_proto.py
#
#  Description:
#    A simple script to analyze OpenFlow updates (none-batched) to see where
#    time is spent.
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    21 April 2021
#
#  Requirements:
#    pip install text_histogram3
#
#  Usage:
#    perf script -s analyze_of_proto.py
#
#  Example:
#    First add the probe for the function call and take some samples:
#      perf probe --del of_*
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_main_poll=main@ovs-vswitchd.c:65'
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_main_poll_ret=main@ovs-vswitchd.c:66'
#      NOTE: Verify the above two line numbers match the code before and after
#            the poll_block() in main(). Do perf prob -x <ovs-vswitchd> -Lmain
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_b_mutex=handle_flow_mod__@ofproto.c:8'
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_a_mutex=handle_flow_mod__@ofproto.c:13'
#      NOTE: Verify the above two line numbers match the code before and after
#            the mutex has been taken!
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_bridge_run=bridge_run'
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_ofproto_run=ofproto_run'
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_connmgr_run=connmgr_run'
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_connmgr_run=connmgr_run%return'
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_handle_of=handle_openflow'
#      perf probe -x /usr/sbin/ovs-vswitchd --add 'of_handle_of=handle_openflow%return'
#      perf probe -x /usr/sbin/ovs-vswitchd --add f_hndl_bar_req=handle_barrier_request'
#      perf record \
#        -e probe_ovs:of_bridge_run \
#        -e probe_ovs:of_ofproto_run \
#        -e probe_ovs:of_connmgr_run \
#        -e probe_ovs:of_connmgr_run__return \
#        -e probe_ovs:of_handle_of \
#        -e probe_ovs:of_handle_of__return \
#        -e probe_ovs:of_b_mutex \
#        -e probe_ovs:of_a_mutex \
#        -e probe_ovs:of_hndl_bar_req \
#        -e probe_ovs:of_main_poll \
#        -e probe_ovs:of_main_poll_ret \
#        -aR sleep 60
#
#    Now you can load the tool trough the script command:
#      perf script -s analyze_of_proto.py


#
# Global imports
#
import os
import sys
from text_histogram3 import histogram

#
# Perf specific imports
#
sys.path.append(os.environ['PERF_EXEC_PATH'] +
                '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *


#
# Global variables
#
delta_events = dict()
last_events = dict()


#
# trace_begin()
#
def trace_begin():
    last_events["start_time"] = 0


#
# trace_end()
#
def trace_end():
    #
    # Print histograms
    #
    histograms = [
        ["main():poll_block() sleep time",
         "probe_ovs__of_main_poll-probe_ovs__of_main_poll_ret"],
        ["bridge_run() delta's",
         "probe_ovs__of_bridge_run-probe_ovs__of_bridge_run"],
        ["Time before of_ofproto_run() executes of_connmgr_run()",
         "probe_ovs__of_ofproto_run-probe_ovs__of_connmgr_run"],
        ["connmgr_run() run time",
         "probe_ovs__of_connmgr_run-probe_ovs__of_connmgr_run__return"],
        ["handle_openflow() run time",
         "probe_ovs__of_handle_of-probe_ovs__of_handle_of__return"],
        ["handle_flow_mod__()'s ovs_mutex_lock(&ofproto_mutex) delay",
         "probe_ovs__of_b_mutex-probe_ovs__of_a_mutex"],
        ["handle_barrier_request() calls related to trace start",
         "start_time-probe_ovs__of_hndl_bar_req"]]

    for entry in histograms:
        print("\n# " + entry[0] + ":")
        if entry[1] in delta_events and len(delta_events[entry[1]]) > 1:
            histogram(delta_events[entry[1]])
            print_first_bucket(delta_events[entry[1]], percentage=20,
                               print_buckets=20)
        else:
            print("# NO SAMPLES POINTS AVAILABLE!!")

    run_time = [
        ["connmgr_run()",
         "probe_ovs__of_connmgr_run-probe_ovs__of_connmgr_run__return"],
        ["handle_openflow()",
         "probe_ovs__of_handle_of-probe_ovs__of_handle_of__return"],
        ["main():poll_block()",
         "probe_ovs__of_main_poll-probe_ovs__of_main_poll_ret"]]

    print()
    for entry in run_time:
        time = 0
        events = 0
        if entry[1] in delta_events and len(delta_events[entry[1]]) > 0:
            time = sum(delta_events[entry[1]])
            events = len(delta_events[entry[1]])

        print("- Total time spend in {:20s}: {:-15,} ns [{} events]".format(
            entry[0], time, events))


    calls = [
        ["handle_flow_mod__()",
         "probe_ovs__of_b_mutex-probe_ovs__of_a_mutex"],
        ["handle_barrier_request()",
         "start_time-probe_ovs__of_hndl_bar_req"]]

    print()
    for entry in calls:
        calls = 0
        if entry[1] in delta_events and len(delta_events[entry[1]]) > 0:
            calls = len(delta_events[entry[1]])

        print("- Total calls to {:25s}: {:-15,}".format(entry[0], calls))


#
# probe_ovs__of_b_mutex()
#
def probe_ovs__of_b_mutex(event_name, context, common_cpu,
                          common_secs, common_nsecs, common_pid, common_comm,
                          common_callchain, __probe_ip, perf_sample_dict):

    stamp_event(event_name, ts(perf_sample_dict))


#
# probe_ovs__of_a_mutex()
#
def probe_ovs__of_a_mutex(event_name, context, common_cpu,
                          common_secs, common_nsecs, common_pid, common_comm,
                          common_callchain, __probe_ip, perf_sample_dict):

    delta_event("probe_ovs__of_b_mutex", event_name, ts(perf_sample_dict))


#
# probe_ovs__of_bridge_run()
#
def probe_ovs__of_bridge_run(event_name, context, common_cpu,
                             common_secs, common_nsecs, common_pid,
                             common_comm, common_callchain, __probe_ip,
                             perf_sample_dict):

    if last_events["start_time"] == 0:
        last_events["start_time"] = ts(perf_sample_dict)

    delta_event(event_name, event_name, ts(perf_sample_dict))
    stamp_event(event_name, ts(perf_sample_dict))


#
# probe_ovs__of_ofproto_run()
#
def probe_ovs__of_ofproto_run(event_name, context, common_cpu,
                              common_secs, common_nsecs, common_pid,
                              common_comm, common_callchain, __probe_ip,
                              perf_sample_dict):

    stamp_event(event_name, ts(perf_sample_dict))


#
# probe_ovs__of_connmgr_run()
#
def probe_ovs__of_connmgr_run(event_name, context, common_cpu,
                              common_secs, common_nsecs, common_pid,
                              common_comm, common_callchain, __probe_ip,
                              perf_sample_dict):

    delta_event("probe_ovs__of_ofproto_run", event_name, ts(perf_sample_dict))
    stamp_event(event_name, ts(perf_sample_dict))


#
# probe_ovs__of_connmgr_run__return()
#
def probe_ovs__of_connmgr_run__return(event_name, context, common_cpu,
                                      common_secs, common_nsecs, common_pid,
                                      common_comm, common_callchain,
                                      __probe_func, __probe_ret_ip,
                                      perf_sample_dict):

    delta_event("probe_ovs__of_connmgr_run", event_name, ts(perf_sample_dict))


#
# probe_ovs__of_handle_of
#
def probe_ovs__of_handle_of(event_name, context, common_cpu,
                            common_secs, common_nsecs, common_pid, common_comm,
                            common_callchain, __probe_ip, perf_sample_dict):

    stamp_event(event_name, ts(perf_sample_dict))


#
# probe_ovs__of_handle_of__return()
#
def probe_ovs__of_handle_of__return(event_name, context, common_cpu,
                                    common_secs, common_nsecs, common_pid,
                                    common_comm, common_callchain,
                                    __probe_func, __probe_ret_ip,
                                    perf_sample_dict):

    delta_event("probe_ovs__of_handle_of", event_name, ts(perf_sample_dict))


#
# probe_ovs__of_hndl_bar_req()
#
def probe_ovs__of_hndl_bar_req(event_name, context, common_cpu,
                               common_secs, common_nsecs, common_pid,
                               common_comm, common_callchain, __probe_ip,
                               perf_sample_dict):

    delta_event("start_time", event_name, ts(perf_sample_dict))

#
# probe_ovs__of_main_poll()
#
def probe_ovs__of_main_poll(event_name, context, common_cpu,
                            common_secs, common_nsecs, common_pid,
                            common_comm, common_callchain, __probe_ip,
                            perf_sample_dict):

    stamp_event(event_name, ts(perf_sample_dict))


#
# probe_ovs__of_main_poll_ret()
#
def probe_ovs__of_main_poll_ret(event_name, context, common_cpu,
                                common_secs, common_nsecs, common_pid,
                                common_comm, common_callchain, __probe_ip,
                                perf_sample_dict):

    delta_event("probe_ovs__of_main_poll", event_name, ts(perf_sample_dict))


#
#
#
def trace_unhandled(event_name, context, event_fields_dict, perf_sample_dict):

    print("! WARNING: Unknown event, \"{}\", in perf trace!".format(event_name),
          file=sys.stderr)


#
# stamp_event()
#
def stamp_event(event, time):
    last_events[event] = time


#
# delta_event()
#
def delta_event(event_a, event_b, time_b, no_reset=False):
    if event_a not in last_events or last_events[event_a] == 0:
        return

    event_name = event_a + "-" + event_b

    if event_name not in delta_events:
        delta_events[event_name] = list()

    delta_events[event_name].append(time_b - last_events[event_a])
    if not no_reset and event_a != "start_time":
        last_events[event_a] = 0


#
# ts()
#
def ts(perf_sample_dict):
    return perf_sample_dict["sample"]["time"]


#
# print_first_bucket()
#
def print_first_bucket(data, buckets=10, print_buckets=10, percentage=0):

    boundaries = []

    if len(data) <= 0:
        return

    if buckets <= 0:
        raise ValueError("Number of buckets must be > 0")

    min_data = min(data)
    max_data = max(data)
    bucket_step = (max_data - min_data) / buckets
    bucket_counts = [0 for x in range(buckets)]
    for x in range(buckets):
        boundaries.append(min(data) + (bucket_step * (x + 1)))

    for value in data:
        for bucket_postion, boundary in enumerate(boundaries):
            if value <= boundary:
                bucket_counts[bucket_postion] += 1
                break

    if percentage <= 0 or (bucket_counts[0] / len(data) * 100) > percentage:
        histogram(data, buckets=print_buckets, maximum=boundaries[0],
                  calc_msvd=False)
