#!/usr/bin/env python

import argparse
import codecs
import datetime
import os
import shutil
import socket
import sys
import hashlib

from threading import Thread
from WebServer import *
from websocket_server import ThreadedWebsocketServer

def output_info(info, args):
    output = "{}: {}".format(datetime.datetime.now(), info).decode("utf-8", "replace")
    print output
    if "websocket_server" in vars(args):
        args.websocket_server.send_message_to_all(output)

def read_from_stdin(args):
    count = 0
    while True:
        count += 1
        con = sys.stdin.readline()
        infos = con.split("><")
        if len(infos) != 4:
            print "error in: " + con
            continue
        pid = infos[0]
        daddr = infos[1]
        cmdline = infos[2]
        data_hex = infos[3].strip() if len(infos[3].strip())%2==0 else "0" + infos[3].strip()
        if not args.watch_list or daddr in args.watch_list:
            path_link = "/proc/{}/exe".format(str(pid))
            path = os.readlink(path_link) if os.path.exists(path_link) else "Unknown"
            log = "pid={}, path={}, cmdline={}, connected to {}".format(pid, path, cmdline, daddr)
            if daddr in args.watch_list:
                log = "pid={}, path={}, cmdline={}, connected to {} ({})".format(pid, path, cmdline, daddr, ",".join(args.watch_list[daddr]))
            if args.content:
                content = codecs.decode(data_hex, "hex")
                log += ", content={}".format(content)
            output_info(log, args)
            try:
                shutil.copy2(path, args.path)
            except:
                pass

def init_args(args):
    watch_list = {}
    if args.ip is not None:
        for single_ip in args.ip:
            watch_list[single_ip] = []
    if args.domain is not None:
        for domain in args.domain:
            ips = socket.gethostbyname_ex(domain)
            for single_ip in ips[2]:
                if single_ip in watch_list:
                    watch_list[single_ip].append(domain)
                else:
                    watch_list[single_ip] = [domain]
    if os.path.exists(args.path) and not os.path.isdir(args.path):
        print "Dump path {} exists, please change path".format(args.path)
    elif not os.path.exists(args.path):
        os.mkdir(args.path)
    if not watch_list:
        print "no watch list specified, monitor all traffic"
    vars(args)["watch_list"] = watch_list
    if args.web:   
        vars(args)["web_server"] = WebServer()
        vars(args)["websocket_server"] = ThreadedWebsocketServer(9001)
    return args

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", nargs="+", help="Evil domain list you would like to monitor.")
    parser.add_argument("-i", "--ip", nargs="+", help="Evil ip list you would like to monitor.")
    parser.add_argument("-t", "--timeout", action="store", type=int, help="Terminate in seconds, set 0 to run forever.")
    parser.add_argument("-p", "--path", action="store", type=str, default="zecops_suspects", help="Dump binary sample to this directory.")
    parser.add_argument("-c", "--content", action="store_true", default=False, help="Show message content.")
    parser.add_argument("-w", "--web", action="store_true", default=False, help="Open web interface.")
    args = parser.parse_args(sys.argv[1:])
    args = init_args(args)
    if args.web:   
        args.web_server.start()
        args.websocket_server.start()
    try:
        read_from_stdin(args)
    except KeyboardInterrupt as e:
        print "exit"
        quit()


if __name__ == "__main__":
    main()
