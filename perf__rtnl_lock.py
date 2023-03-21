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
#    perf__rtnl_lock.py
#
#  Description:
#    Simple perf script to see how long rtnl_lock takes.
#
#  Author:
#    Eelco Chaudron
#
#  Notes:
#    Perf input should be as follows:
#      perf probe --add rtnl_lock --add rtnl_lock%return \
#        --add __rtnl_unlock%return --add __rtnl_unlock \
#        --add rtnl_lock_killable --add 'rtnl_lock_killable%return $retval' \
#        --add rtnl_trylock --add 'rtnl_trylock%return $retval' \
#        --add refcount_dec_and_rtnl_lock \
#        --add 'refcount_dec_and_rtnl_lock%return $retval'
#      perf record -g --call-graph dwarf -e probe:__rtnl_unlock \
#        -e probe:__rtnl_unlock__return  -e probe:rtnl_lock \
#        -e probe:rtnl_lock__return -e probe:rtnl_lock_killable \
#        -e probe:rtnl_lock_killable__return -e probe:rtnl_trylock \
#        -e probe:rtnl_trylock__return -e probe:refcount_dec_and_rtnl_lock \
#        -e probe:refcount_dec_and_rtnl_lock__return --mmap-pages=128000
#
#    Run script as follows
#      perf script -s ./perf__rtnl_lock.py
# 
#    If you do not want the call chain, run it as:
#      NO_CALLCHAIN=1 perf script -s ./perf__rtnl_lock.py
# 
#    If you want to use the rtnl_unlock() call stack use:
#      USE_UNLOCK=1 perf script -s ./perf__rtnl_lock.py
#
from __future__ import print_function

import os
import sys

sys.path.append(os.environ['PERF_EXEC_PATH'] +
                '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

lock_take_times = {}
locks = []


def probe__rtnl_lock(event_name, context, common_cpu,
                     common_secs, common_nsecs, common_pid,
                     common_comm, common_callchain, __probe_ip,
                     perf_sample_dict):

    global lock_take_times

    lock_take_times[perf_sample_dict["sample"]["tid"]] = {
        "type": "rtnl_lock()",
        "nsecs": (common_secs * 1000000000) + common_nsecs,
        "locked_nsecs": 0,
        "callchain": common_callchain}

def probe__rtnl_lock_killable(event_name, context, common_cpu,
                              common_secs, common_nsecs, common_pid,
                              common_comm, common_callchain, __probe_ip,
                              perf_sample_dict):

    global lock_take_times

    lock_take_times[perf_sample_dict["sample"]["tid"]] = {
        "type": "rtnl_lock_killable()",
        "nsecs": (common_secs * 1000000000) + common_nsecs,
        "locked_nsecs": 0,
        "callchain": common_callchain}


def probe__rtnl_trylock(event_name, context, common_cpu,
                        common_secs, common_nsecs, common_pid, common_comm,
                        common_callchain, __probe_ip, perf_sample_dict):
    global lock_take_times

    lock_take_times[perf_sample_dict["sample"]["tid"]] = {
        "type": "rtnl_trylock()",
        "nsecs": (common_secs * 1000000000) + common_nsecs,
        "locked_nsecs": 0,
        "callchain": common_callchain}

def probe__refcount_dec_and_rtnl_lock(event_name, context, common_cpu,
                                      common_secs, common_nsecs, common_pid,
                                      common_comm, common_callchain,
                                      __probe_ip, perf_sample_dict):

    lock_take_times[perf_sample_dict["sample"]["tid"]] = {
        "type": "refcount_dec_and_rtnl_lock()",
        "nsecs": (common_secs * 1000000000) + common_nsecs,
        "locked_nsecs": 0,
        "callchain": common_callchain}


def probe__rtnl_lock__return(event_name, context, common_cpu,
                             common_secs, common_nsecs, common_pid,
                             common_comm, common_callchain, __probe_ip,
                             __probe_ret_ip, perf_sample_dict):
    global lock_take_times

    lock = lock_take_times[perf_sample_dict["sample"]["tid"]]
    lock["locked_nsecs"] = (common_secs * 1000000000) + common_nsecs
    lock_take_times[perf_sample_dict["sample"]["tid"]] = lock


def probe__rtnl_lock_killable__return(event_name, context, common_cpu,
                                      common_secs, common_nsecs, common_pid,
                                      common_comm, common_callchain,
                                      __probe_func, __probe_ret_ip, arg1,
                                      perf_sample_dict):
    global lock_take_times

    # If return value is 0, lock was taken.
    if arg1 == 0:
        lock = lock_take_times[perf_sample_dict["sample"]["tid"]]
        lock["locked_nsecs"] = (common_secs * 1000000000) + common_nsecs
        lock_take_times[perf_sample_dict["sample"]["tid"]] = lock
    else:
        del lock_take_times[perf_sample_dict["sample"]["tid"]]


def probe__rtnl_trylock__return(event_name, context, common_cpu,
                                common_secs, common_nsecs, common_pid,
                                common_comm, common_callchain, __probe_func,
                                __probe_ret_ip, arg1, perf_sample_dict):
    global lock_take_times

    # If return value is 1, lock was taken.
    if arg1 == 1:
        lock = lock_take_times[perf_sample_dict["sample"]["tid"]]
        lock["locked_nsecs"] = (common_secs * 1000000000) + common_nsecs
        lock_take_times[perf_sample_dict["sample"]["tid"]] = lock
    else:
        del lock_take_times[perf_sample_dict["sample"]["tid"]]


def probe__refcount_dec_and_rtnl_lock__return(event_name, context, common_cpu,
                                              common_secs, common_nsecs,
                                              common_pid, common_comm,
                                              common_callchain, __probe_func,
                                              __probe_ret_ip, arg1,
                                              perf_sample_dict):
    global lock_take_times

    # If return value is true, lock was taken. If false lock might have
    # been taken and released...
    if arg1 != 0:
        lock = lock_take_times[perf_sample_dict["sample"]["tid"]]
        lock["locked_nsecs"] = (common_secs * 1000000000) + common_nsecs
        lock_take_times[perf_sample_dict["sample"]["tid"]] = lock
    else:
        del lock_take_times[perf_sample_dict["sample"]["tid"]]



def probe____rtnl_unlock(event_name, context, common_cpu,
                         common_secs, common_nsecs, common_pid,
                         common_comm, common_callchain, __probe_ip,
                         perf_sample_dict):
    global lock_take_times

    if os.getenv('USE_UNLOCK') is None:
        return

    try:
        lock = lock_take_times[perf_sample_dict["sample"]["tid"]]
    except KeyError:
        return

    lock["callchain"] = common_callchain
    lock_take_times[perf_sample_dict["sample"]["tid"]] = lock


def probe____rtnl_unlock__return(event_name, context, common_cpu,
                               common_secs, common_nsecs, common_pid,
                               common_comm, common_callchain,
                               __probe_func, __probe_ret_ip,
                               perf_sample_dict):
    global lock_take_times
    global locks

    try:
        lock = lock_take_times[perf_sample_dict["sample"]["tid"]]
    except KeyError:
        if os.getenv('NO_WARN') is None:
            locks.append(
                {"type": "WARNING",
                 "lock_ts": (common_secs * 1000000000) + common_nsecs,
                 "comm": common_comm,
                 "callchain": common_callchain})
        return

    locks.append(
        {"lock_ts": lock["nsecs"],
         "locked_ts": lock["locked_nsecs"],
         "unlock_ts": (common_secs * 1000000000) + common_nsecs,
         "comm": common_comm,
         "type": lock["type"],
         "callchain": lock["callchain"]})

    del lock_take_times[perf_sample_dict["sample"]["tid"]]


def trace_unhandled(event_name, context, event_fields_dict, perf_sample_dict):
    print("UNKOWN EVENT {}:".format(event_name))
    print(get_dict_as_string(event_fields_dict))
    print('Sample: {'+get_dict_as_string(perf_sample_dict['sample'], ', ')+'}')


def get_dict_as_string(a_dict, delimiter=' '):
    return delimiter.join(['%s=%s' % (k, str(v))for k, v in
                           sorted(a_dict.items())])


def trace_end():
    global locks

    print("{}, {}, {}, {}, {}, {}, {}".format("lock@", "locked@", "unlock@",
                                              "delta_ms", "delta_locking",
                                              "delta_locked",
                                              "comm"))

    locks = sorted(locks, key=lambda sample: sample["lock_ts"])
    for lock in locks:
        if lock["type"] == "WARNING":
            print("!WARNING: Got unlock without lock for {} @ {}".format(
                lock["comm"], lock["lock_ts"]))

            if os.getenv('NO_CALLCHAIN') is None:
                for node in lock["callchain"]:
                    if 'sym' in node:
                        print("!\t[%x] %s" % (node['ip'], node['sym']['name']))
                    else:
                        print("!\t[%x]" % (node['ip']))

            continue

        delta_time_ms = int((lock["unlock_ts"] - lock["lock_ts"]) / 1000000)
        delta_locking = lock["locked_ts"] - lock["lock_ts"]
        delta_locked = lock["unlock_ts"] - lock["locked_ts"]

        print("{}, {}, {}, {}, {}, {}, \"{}\", {}".format(lock["lock_ts"],
                                                          lock["locked_ts"],
                                                          lock["unlock_ts"],
                                                          delta_time_ms,
                                                          delta_locking,
                                                          delta_locked,
                                                          lock["comm"],
                                                          lock["type"]))

        if os.getenv('NO_CALLCHAIN') is None:
            for node in lock["callchain"]:
                if 'sym' in node:
                    print("#\t[%x] %s" % (node['ip'], node['sym']['name']))
                else:
                    print("#\t[%x]" % (node['ip']))
