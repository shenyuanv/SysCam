#!/usr/bin/env python

import codecs
import datetime
import os
import shutil
import socket
import sys
import logging
import struct

from distutils.spawn import find_executable

dump_path = "zecops_suspects"


def read_from_stdin(watch_list, dns_list):
    count = 0
    while True:
        count += 1
        con = sys.stdin.readline()
        infos = con.split("><")
        if len(infos) != 4:
            logging.info("Illegal info:" + con)
            continue
        pid = infos[0]
        daddr = infos[1]
        cmdline = infos[2]
        data_hex = infos[3].strip()
        data_str = None
        path = None
        if len(data_hex)%2 != 0:
            data_hex = "0" + data_hex
        data_str = codecs.decode(data_hex, "hex")
        if not watch_list or daddr in watch_list:
            path = get_path(pid, cmdline.split(" ")[0])
            log = "pid=%s, path=%s, cmdline=%s, connected to %s" % (pid, path, cmdline, daddr)
            if watch_list and daddr in watch_list:
                log = "pid=%s, path=%s, cmdline=%s, connected to %s (%s)" % (pid, path, cmdline, daddr, ",".join(watch_list[daddr]))
            if data_str:
                log += ", content=%s" % data_str
            logging.warning(log)
        if dns_list and contains_dns(data_str, dns_list):
            path = get_path(pid, cmdline.split(" ")[0])
            log = "pid=%s, path=%s, cmdline=%s, send dns query %s to server %s" % (pid, path, cmdline , contains_dns(data_str, dns_list), daddr)
            logging.warning(log)
        if not path:
            continue
        try:
            shutil.copy2(path, dump_path)
        except:
            pass

def contains_dns(data_str, dns_list):
    if not data_str or not data_str.strip():
        return None
    for dns in dns_list:
        if dns in data_str:
            return dns_list[dns]
    return None

def get_path(pid, execname):
    link_path = "/proc/%s/exe" % pid
    path = None
    if os.path.exists(link_path):
        path = os.readlink(link_path)
    else:
        path = find_executable(execname)
    return path

def domain2dns(domain):
    urls = domain.split(".")
    dns_str = ""
    for url in urls:
        dns_str += struct.pack("B", len(url))
        dns_str += url
    return dns_str

def init_args(domain_list):
    watch_list = {}
    dns_list = {}
    for domain in domain_list:
        dns_str = domain2dns(domain)
        dns_list[dns_str] = domain
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
        print "Dump path %s exists, please change path" % dump_path
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
    return watch_list, dns_list

def main():
    watch_list, dns_list = init_args(sys.argv[1:])
    try:
        read_from_stdin(watch_list, dns_list)
    except KeyboardInterrupt:
        print "logs saved to ", dump_path


if __name__ == "__main__":
    main()
