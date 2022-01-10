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
#    objdump_hook.py
#
#  Description:
#    Simple script to get objdump info, and translate it to perf
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    3 April 2018
#
#  Notes:
#

#
# Imports
#
import re
import subprocess


#
# Ugly but I'm lazy ;)
#
__addr2line_cache = dict()


#
# Read in all elf symbols for Functions()
#
def elf_import(file):
    functions = dict()
    function_re = "([0-9a-fA-F]+) ......F \.text\s+([0-9a-fA-F]+)\s+(.*)\s*.*"

    output = subprocess.check_output(['objdump', '-t', file]).split('\n')
    for line in output:
        match = re.match(function_re, line)
        if match is not None:
            if match.group(3) not in functions:
                functions[match.group(3)] = [int(match.group(1), 16),
                                             int(match.group(2), 16)]

    return functions


#
# Translate perf record IP into offset using objdump data
#
def translate_perf_ip_2_user_address(functions, name, start, end, ip):

    if name in functions:
        if (end - start) != functions[name][1]:
            return -1

        return ip - start + functions[name][0]
    else:
        return -2

    return 0


#
# addr2line with cache
#
def addr2line(file, pc):

    global __addr2line_cache

    if file not in __addr2line_cache:
        __addr2line_cache[file] = dict()

    if pc in __addr2line_cache[file]:
        return __addr2line_cache[file][pc]

    output = subprocess.check_output(['addr2line', '-p', '-f',
                                      '-e', file, hex(pc)]).split('\n')[0]

    __addr2line_cache[file][pc] = output
    return output


#
# Main()
#
def main():
    file = "/home/echaudro/Documents/Scratch/ovs_txbatch/vswitchd/ovs-vswitchd"

    functions = elf_import(file)

    faddr = translate_perf_ip_2_user_address(functions, "pmd_thread_main",
                                             3370320, 3372058, 3371131)

    print(addr2line(file, faddr))
    print __addr2line_cache
    print(addr2line(file, faddr))
    print __addr2line_cache


#
# Start main() as default entry point...
#
if __name__ == '__main__':
    exit(main())
