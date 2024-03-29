# perf script event handlers, generated by perf script -g python
# Licensed under the terms of the GNU GPL License version 2

# The common_* event handler fields are the most useful fields common to
# all events.  They don't necessarily correspond to the 'common_*' fields
# in the format files.  Those fields not available as handler params can
# be retrieved using Python functions of the form common_*(context).
# See the perf-script-python Documentation for the list of available functions.

#
#
# perf probe --add 'cp_in=__gnet_stats_copy_basic'
# perf probe --add 'cp_out=__gnet_stats_copy_basic%return'
# perf record -e probe:cp_in -e probe:cp_out -aR sleep 60
#
# perf script -s ./analyze_perf_delta.py -i perf.data_RUN1_FIX

import os
import sys

sys.path.append(os.environ['PERF_EXEC_PATH'] +
                '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from Core import *


last_in = dict()
total = 0
events = 0

def trace_begin():
    print("in trace_begin")

def trace_end():
    global total
    global events

    print("in trace_end")
    print("average {} ns".format(total/events))

def probe_ovs__pmdrcuq_in(event_name, context, common_cpu,
    common_secs, common_nsecs, common_pid, common_comm,
    common_callchain, __probe_ip):

    global last_in
    last_in[common_cpu] = (common_secs * 1000000000) + common_nsecs

def probe_ovs__pmdrcuq_out__return(event_name, context, common_cpu,
    common_secs, common_nsecs, common_pid, common_comm,
    common_callchain, __probe_func, __probe_ret_ip):

    global last_in
    global total
    global events

    if common_cpu in last_in:
        last_out = (common_secs * 1000000000) + common_nsecs
        delta = (last_out - last_in[common_cpu])
        #print("{}, {}".format(delta, common_cpu))
        print(delta)
        total += delta
        events += 1
        del last_in[common_cpu]


def trace_unhandled(event_name, context, event_fields_dict):
    print(event_name)
    print(' '.join(['%s=%s'%(k,str(v))for k,v in sorted(event_fields_dict.items())]))

def print_header(event_name, cpu, secs, nsecs, pid, comm):
    print("%-20s %5u %05u.%09u %8u %-20s " %
          (event_name, cpu, secs, nsecs, pid, comm))
