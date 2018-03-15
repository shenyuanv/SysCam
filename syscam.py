#!/usr/bin/env python

import codecs
import datetime
import os
import shutil
import socket
import sys
import logging
import struct
import json

from distutils.spawn import find_executable

dump_path = "zecops_suspects"


def read_from_stdin(watch_list, dns_list):
    count = 0
    while True:
        count += 1
        con = sys.stdin.readline()
        infos = con.split("><")
        if len(infos) != 4:
            #logging.info("Illegal info:" + con)
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
        now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        path = get_path(pid, cmdline.split(" ")[0])
        log_json = None
        if not watch_list or daddr in watch_list:
            log_json = {"time":now, "pid":pid, "path":path, "cmdline":cmdline, "daddr":daddr}
        if watch_list and daddr in watch_list:
            log_json["domain"] = watch_list[daddr]         
        if dns_list and contains_dns(data_str, dns_list):
            log_json["dns"] = contains_dns(data_str, dns_list)  
        if log_json and "pid" in log_json:
            logging.warning(json.dumps(log_json))
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
    formatter = logging.Formatter('%(message)s')
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
