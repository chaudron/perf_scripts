#!/usr/bin/python
#
#  Copyright 2018, Eelco Chaudron
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
#    analyze_perf_pmd_syscall.py
#
#  Description:
#    Simple script to dump syscall invocation, with grouped backtraces.
#    The backtraces only include symbols found in the ELF binary.
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    4 April 2018
#
#  Usage:
#    perf script -s analyze_perf_pmd_syscall.py <ELF_BINARY> [<OVS_ADDR_OFFSET]
#
#  Example:
#    Capture perf data for example from Open vSwitch's PMD threads with the
#    following command:
#
#      perf record -e raw_syscalls:sys_enter -s --call-graph dwarf \
#        --per-thread -g -i -t \
#        `ps -To tid,comm \`pidof ovs-vswitchd\` | \
#        grep pmd | awk '{$1=$1};1' | cut -d " " -f 1 | xargs | \
#        sed -e 's/ /,/g'`
#
#    Once the data is in, execute the following to generate a report:
#
#      perf script -s analyze_perf_pmd_syscall.py /usr/sbin/ovs-vswitchd
#
#    NOTE: The above only works if the /usr/sbin/ovs-vswitchd has debug symbols
#          or debug symbols are available in /usr/lib/debug/.build-id/
#
#    NOTE: Based on the kernel version/configuration the ovs-vswitchd reported
#          instruction pointer might not be at a zero offset, causing the
#          addr2line lookups to fail. If this is the case, the backtrace
#          output will have entries like
#          "seq_read() @ <source information unknown>". To fix this, you could
#          manually add the offset to the script. The information we need is
#          available in the trace data, but unfortunately not available
#          directly through the script. Here we assume a single ovs-vswitchd
#          daemon was running and was not restarted during the trace capture:
#
#            $ perf script -i perf_entry.data --show-mmap-events | \
#              grep "r-xp /usr/sbin/ovs-vswitchd"
#            ovs-vswitchd     0 [000]     0.000000: PERF_RECORD_MMAP2 283211/283211: [0x5573647bd000(0xc4c000) @ 0 fd:00 67462292 0]: r-xp /usr/sbin/ovs-vswitchd     # noqa: E501
#
#          You need the use the 0x5573647bd000 value as the <OVS_ADD_OFFSET>.
#

#
# Global imports
#
import ast
import os
import re
import subprocess
import sys


#
# Perf specific imports
#
sys.path.append(os.environ['PERF_EXEC_PATH'] +
                '/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from Core import autodict         # noqa: E402
from Util import syscall_name     # noqa: E402


#
# Global variables
#
__addr2line_cache = dict()
all_backtraces = autodict()
all_syscalls = autodict()
all_functions = dict()
ovs_address_offset = 0
processed_events = 0


#
# Read symbols from obj file
#
def read_symbols(file):
    functions = dict()
    function_re = r"([0-9a-fA-F]+) ......F \.text\s+([0-9a-fA-F]+)\s+(.*)\s*.*"
    no_symbols_re = r"^no symbols$"

    output = subprocess.check_output(['objdump', '-t', file]). \
        decode('utf-8').split('\n')

    for line in output:
        if re.match(no_symbols_re, line):
            return None

        match = re.match(function_re, line)
        if match is not None:
            if match.group(3) not in functions:
                functions[match.group(3)] = [int(match.group(1), 16),
                                             int(match.group(2), 16)]

    return functions


#
# Read in all elf symbols for Functions()
#
def elf_import(file):
    functions = read_symbols(file)

    if functions is None:
        output = subprocess.check_output(['readelf', '-n', file])
        match = re.search("Build ID: ([0-9a-fA-F]+)", output.decode('utf-8'))
        if match is None:
            sys.exit("ERROR: Can't find build ID to read debug symbols!")

        dbg_file = "/usr/lib/debug/.build-id/{}/{}.debug".format(
            match.group(1)[:2], match.group(1)[2:])
        print("- No symbols in binary file, will try \"{}\"".format(dbg_file))

        functions = read_symbols(dbg_file)

        # Not the best way, but it will do for now...
        global bin_file
        bin_file = dbg_file

    print("- Done reading binary elf symbols, total of {} functions found.".
          format(len(functions)))

    return functions


#
# Translate perf record IP (instruction pointer) into offset using objdump data
#
def translate_perf_ip_2_user_address(functions, name, start, end, ip):
    if name not in functions:
        return -1

    function_start = functions[name][0]
    function_end = function_start + functions[name][1]

    if function_start != start or function_end != end:
        return -2

    #
    # We have to use this ugly ovs_address_offset here are we do not have
    # access to the offset, or map information. See the following for more
    # details on what we miss:
    #   https://elixir.bootlin.com/linux/v5.16.5/source/tools/perf/util/scripting-engines/trace-event-python.c#L736
    #
    address = ip - ovs_address_offset

    if address >= start and address <= end:
        return address

    return -3


#
# addr2line with cache
#
def addr2line(file, pc):
    global __addr2line_cache

    if file not in __addr2line_cache:
        __addr2line_cache[file] = dict()

    if pc in __addr2line_cache[file]:
        return __addr2line_cache[file][pc]

    with open(os.devnull, 'w') as devnull:
        output = subprocess.check_output(['addr2line', '-p', '-f', '-i',
                                          '-e', file, hex(pc)],
                                         stderr=devnull). \
                                         decode('utf-8').split('\n')[0]

    __addr2line_cache[file][pc] = output
    return output


#
# Get instruction pointers source code info, if exists
def get_ip_source_info(node):
    if 'sym' in node:
        faddr = translate_perf_ip_2_user_address(all_functions,
                                                 node['sym']['name'],
                                                 node['sym']['start'],
                                                 node['sym']['end'],
                                                 node['ip'])

        if faddr == -1:
            # This is a none OVS symbol and we do not want to return it.
            return None

        if faddr > 0:
            source_line = addr2line(bin_file, faddr)
            if source_line is not None and source_line != "":
                return source_line

        return "<source information unknown>"


#
# Get full backtrace for binary file
#
def get_ovs_backtrace_only(callchain):
    bin_callchain = list()
    for node in callchain:
        if 'sym' in node:
            source = get_ip_source_info(node)
            if source is not None:
                bin_callchain.append([node['sym']['name'], source])

    return bin_callchain


#
# Get syscall summary
#
def show_syscall_summary():
    print("\nSYSCALL events:")
    print("===============\n")

    print("{:40}  {:>10}".format("Syscall", "Count"))
    print("{:40}  {:>10}".format("----------------------------------------",
                                 "----------"))

    for id, id_val in sorted(all_syscalls.items(), reverse=True):

        total = 0
        print("{:40}".format(syscall_name(id)))

        for comm, comm_val in sorted(id_val.items(),
                                     key=lambda kv: (kv[1], kv[0])):
            print("    {:36}  {:>10}".format(comm, comm_val))
            total += comm_val

        print("    {:36}  {:>10}+".format("", "-" * len(str(total))))
        print("    {:36}  {:>10}\n".format("TOTAL", total))


#
# Show callback results
#
def show_callback_results():
    print("\nCALLBACK events:")
    print("================\n")

    for bt, bt_val in sorted(all_backtraces.items()):
        bt_list = ast.literal_eval(bt)
        for i, bt_entry in enumerate(bt_list):
            print("#{:<2} {}() @ {}".format(i, bt_entry[0], bt_entry[1]))

        print("\n  {:40}  {:>10}".format("Syscall", "Count"))
        print("  {:40}  {:>10}".
              format("----------------------------------------",
                     "----------"))

        for id, id_val in sorted(bt_val.items(), reverse=True):
            total = 0
            print("  {:40}".format(syscall_name(id)))

            for comm, comm_val in sorted(id_val.items(),
                                         key=lambda kv: (kv[1], kv[0])):
                print("      {:36}  {:>10}".format(comm, comm_val))
                total += comm_val

            print("      {:36}  {:>10}+".format("", "-" * len(str(total))))
            print("      {:36}  {:>10}".format("TOTAL", total))

        print("\n")


#
# Beginning of the trace
#
def trace_begin():
    global all_functions

    all_functions = elf_import(bin_file)


#
# End of the trace, show results
#
def trace_end():
    print("- Done processing {} sys_enter events.".format(processed_events))
    print("- Results:")
    show_syscall_summary()
    show_callback_results()


#
# Callback for syscall events
#
def raw_syscalls__sys_enter(event_name, context, common_cpu,
                            common_secs, common_nsecs, common_pid,
                            common_comm, common_callchain, id, args):
    global processed_events

    processed_events += 1

    try:
        all_syscalls[id][common_comm] += 1
    except TypeError:
        all_syscalls[id][common_comm] = 1

    bt = get_ovs_backtrace_only(common_callchain)
    if bt is not None:
        try:
            all_backtraces[str(bt)][id][common_comm] += 1
        except TypeError:
            all_backtraces[str(bt)][id][common_comm] = 1


#
# Show warning when unhandled events are encountered
#
def trace_unhandled(event_name, context, event_fields_dict):
    if event_name != "raw_syscalls__sys_exit":
        print("WARNING: Unknown event: {}".format(event_name))


#
# Handle command line argument
#
if len(sys.argv) < 2 or len(sys.argv) > 3:
    sys.exit("perf script -s analyze_perf_pmd_syscall.py <ELF_BINARY> "
             "[<OVS_ADD_OFFSET]")

bin_file = sys.argv[1]
if len(sys.argv) > 2:
    ovs_address_offset = int(sys.argv[2], 0)
