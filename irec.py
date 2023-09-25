#  irec.py
#
#  Copyright 2020 Namjun Jo <kirasys@theori.io>
#
#  Redistribution and use in source and binary forms, with or without modification,
#  are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#    * Neither the name of {{ project }} nor the names of its contributors
#      may be used to endorse or promote products derived from this software
#      without specific prior written permission.
# 
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
#  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import json
import angr
import pprint
import logging
import datetime
import argparse
import boltons.timeutils

from projects import angpt

from projects import wdm

class FullPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))

def to_hex_simple(d):
    hex_data = {}
    for key, value in d.items():
        hex_key = hex(key)
        hex_value = {k: hex(v) for k, v in value.items()}
        hex_data[hex_key] = hex_value
    return hex_data

def to_hex_xref(d):
    hex_data = {}
    for key, value_list in d.items():
        hex_key = hex(key)
        hex_value_list = []
        for item in value_list:
            hex_item = {'addr': hex(item['addr']), 'mode': item['mode']}
            hex_value_list.append(hex_item)
        hex_data[hex_key] = hex_value_list
    return hex_data

def mkdir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

def parse_is_file(dirname):
    if not os.path.isfile(dirname):
        msg = "{0} is not a file".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

def setupLogging(args):
    level = getattr(logging, args.log)
    logging.getLogger('angr').setLevel(level)
    return

def parseArguments():
    parser = argparse.ArgumentParser(description='Automatic Driver Analysis', usage='driver.py [-d, --driver] driverPath [-L, --log] --user-static [ioctl addr] logLevel [-s, --skip] [-o, --output] output')
    parser.add_argument('-driver', metavar='<file>', required=True, action=FullPath,
                        type=parse_is_file, help='path to the driver')
    parser.add_argument('-log', default='FATAL', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'FATAL'), help='set a logging level')
    parser.add_argument('-skip', default=False, action='store_true', help='skip the functions that do not need to be analyzed')
    parser.add_argument('-output', metavar='<file>', action=FullPath, help='path to a output file')
    parser.add_argument('--user-static', default=False, help='ioctl address ex) 0x114bc')
    return parser, parser.parse_args()

if __name__ == '__main__':
    parser, args = parseArguments()
    setupLogging(args)
    
    mkdir('result')

    if len(sys.argv) <= 1:
        print("usage: %s" % parser.usage)
        sys.exit()

    start_time = datetime.datetime.utcnow()
    driver = wdm.WDMDriverAnalysis(args.driver, skip_call_mode=args.skip)
    
    if driver.isWDM():
        print("Finding DeviceName...")
        device_name = driver.find_device_name()
        print("\t> DeviceName : %s\n" % device_name)
        
        print("Finding DispatchDeviceControl...")
        mj_device_control_func = driver.find_dispatcher(args.user_static)
        print("\t> DispatchDeviceControl : 0x%x\n" % mj_device_control_func)

        print("Recovering the IOCTL interface...")
        ioctl_interface, ioctl_infos = driver.recovery_ioctl_interface()
        print("\t> IOCTL Interface :")
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(ioctl_interface)

        elapsed = boltons.timeutils.decimal_relative_time(start_time, datetime.datetime.utcnow())
        print("\nCompleted ({0:.1f} {1})".format(*elapsed))

        print("\t> [angPT] IOCTL RIP INFO :")
        ioctl_infos_hex = to_hex_simple(ioctl_infos)
        pp.pprint(ioctl_infos_hex)

        try:
            angPT = angpt.angPTObject(args.driver, mj_device_control_func, ioctl_infos)
            xref_spider = to_hex_xref(angPT.go_analysis())
            print('[angPT] success')

        except Exception as e:
            print('[angPT] fail')
            print(e)
            xref_spider = 'error'
        
        if '/' in args.driver:
            output_name = args.driver.split('/')[-1].split('.')[0]
        else:
            output_name = args.driver.split('.')[0]
        mkdir(f'result/{output_name}')
        
        with open(f'result/{output_name}/{output_name}.json', "w") as json_file:
            json.dump(ioctl_interface, json_file)
        with open(f'result/{output_name}/{output_name}.rip', "w") as json_file:
            json.dump(ioctl_infos_hex, json_file)
        with open(f'result/{output_name}/{output_name}.xref', "w") as json_file:
            json.dump(xref_spider, json_file)
        
    else:
        print("[!] '%s' is not a supported driver." % args.driver)
        sys.exit()
