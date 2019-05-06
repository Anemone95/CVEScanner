#!/usr/bin/env python
# -*- coding=utf-8 -*-
"""Usage:
mt_console start -F <jar_file> [-v] [-t <thread_num>] [--mongodb=<ip:port>]
mt_console stop
mt_console bash
mt_console (-h|--help)
Options:
  -h --help      Show this screen.
  start:         Start a scan.
      -v                Verbose log.
      -d                Debug log.
  stop          Stop a scan.
  bash          start a bash.
"""
import json
import logging
import os
import shutil
import subprocess
import time
from docopt import docopt

from controllers import core


def start(path, log_level=logging.INFO, thread_num=5, mongodb=("127.0.0.1",27017)):
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(filename)s : %(funcName)s() : %(message)s',
                        level=log_level)
    cveinfo='{}.cveinfo'.format(path)
    with open(cveinfo, 'w+') as f:
        f.write("nonce")

    res = core.main(path, thread_num, mongodb)
    print(json.dumps(res))
    os.remove(cveinfo)

def stop():
    files = os.listdir('.')
    rmfiles = []
    for filename in files:
        if filename.endswith('.cveinfo'):
            jar_name=".".join(filename.split(".")[:-1])
            logging.info("kill: "+jar_name)
            cmd = 'ps -ef|grep -E "start -F .*{}|\sPID"'.format(jar_name)
            ps_res = os.popen(cmd).readlines()
            flags = ps_res[0].split()
            pid_idx = flags.index("PID")
            for each_line in ps_res[1:]:
                pid = each_line.split()[pid_idx]
                if 'grep' not in each_line:
                    cmd = "kill {}".format(pid)
                    logging.info(cmd)
                    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()
                    if process.returncode:
                        raise Exception(stderr)
            rmfiles.append(filename)

    for each in rmfiles:
        failed_times=10
        rmfile=os.path.join('.', each)
        while failed_times and os.path.exists(rmfile):
            try:
                if os.path.isfile(rmfile):
                    os.remove(rmfile)
                else:
                    shutil.rmtree(rmfile)
                failed_times = 0
            except OSError as e:
                logging.error(e)
                failed_times -= 1
                time.sleep(1)
                logging.error('Retry after 1 seconds.')
    logging.info('Stop success.')


def main():
    arguments = docopt(__doc__, version='1.0.0')
    if arguments["start"]:
        if arguments["-v"]:
            log_level = logging.DEBUG
        else:
            log_level = logging.ERROR

        if arguments['-t']:
            thread_num=int(arguments["<thread_num>"])
        else:
            thread_num=10

        if arguments["--mongodb"]:
            mongodb=arguments["--mongodb"].split(":")
            mongodb[1]=int(mongodb[1])
        else:
            mongodb=("127.0.0.1", 27017)

        start(arguments["<jar_file>"], log_level=log_level, thread_num=thread_num, mongodb=mongodb)

    elif arguments["stop"]:
        stop()
    elif arguments["bash"]:
        os.system("bash")


if __name__ == '__main__':
    main()
