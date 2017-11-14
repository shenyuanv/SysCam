#!/usr/bin/env python

import codecs
import datetime
import os
import shutil
import socket
import sys
import logging

from distutils.spawn import find_executable

dump_path = "zecops_suspects"


def read_from_stdin(watch_list):
    count = 0
    while True:
        count += 1
        con = sys.stdin.readline()
        infos = con.split("><")
        if len(infos) != 4:
            logging.warning("Illegal info:" + con)
            continue
        pid = infos[0]
        daddr = infos[1]
        cmdline = infos[2]
        data_hex = infos[3].strip()
        if len(data_hex)%2 != 0:
            data_hex = "0" + data_hex
        if not watch_list or daddr in watch_list:
            path_link = "/proc/%s/exe" % pid
            if os.path.exists(path_link):
                path = os.readlink(path_link)
            elif find_executable(cmdline.split(" ")[0]):
                path = find_executable(cmdline.split(" ")[0])
            else:
                path = "Unknown"

            log = "pid=%s, path=%s, cmdline=%s, connected to %s" % (pid, path, cmdline, daddr)
            if watch_list and daddr in watch_list:
                log = "pid=%s, path=%s, cmdline=%s, connected to %s (%s)" % (pid, path, cmdline, daddr, ",".join(watch_list[daddr]))
            if data_hex:
                content = codecs.decode(data_hex, "hex")
                log += ", content=%s" % content
            logging.warning(log)
            try:
                shutil.copy2(path, dump_path)
            except:
                pass

def init_args(domain_list):
    watch_list = {}
    if domain_list is None or len(domain_list) < 1:
        watch_list = None
    for domain in domain_list:
        try:
            ips = socket.gethostbyname_ex(domain)
            for single_ip in ips[2]:
                if single_ip in watch_list:
                    watch_list[single_ip].append(domain)
                else:
                    watch_list[single_ip] = [domain]
        except Exception: 
            pass
    if os.path.exists(dump_path) and not os.path.isdir(dump_path):
        print "Dump path {} exists, please change path".format(dump_path)
    elif not os.path.exists(dump_path):
        os.mkdir(dump_path)

    logging.basicConfig(filename=dump_path + "/connections.log", level=logging.INFO)
    rootLogger = logging.getLogger()
    stHandler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    stHandler.setFormatter(formatter)
    rootLogger.addHandler(stHandler)
    if not watch_list:
        logging.info("no watch list specified, monitor all traffic")
    return watch_list

def main():
    watch_list = init_args(sys.argv[1:])
    try:
        read_from_stdin(watch_list)
    except KeyboardInterrupt:
        print "logs saved to ", dump_path


if __name__ == "__main__":
    main()
