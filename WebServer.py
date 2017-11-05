#!/usr/bin/env python

import sys
import BaseHTTPServer
import threading
import requests

from SimpleHTTPServer import SimpleHTTPRequestHandler


class WebServer(threading.Thread):
    def __init__(self, address="127.0.0.1", port=8000):
        threading.Thread.__init__(self)
        self.address = address
        self.port = port
        self.stop_flag = threading.Event()
        self.daemon = True

    def start_server(self):
        return self

    def run(self):
        HandlerClass = SimpleHTTPRequestHandler
        ServerClass  = BaseHTTPServer.HTTPServer
        port = 8000
        server_address = (self.address, self.port)
        httpd = ServerClass(server_address, HandlerClass)
        
        sa = httpd.socket.getsockname()
        print "Serving HTTP on", self.address, "port", self.port, "..."
        self.httpd = httpd
        while not self.stop_flag.is_set():
            httpd.handle_request()

    def stop(self):
        self.stop_flag.set()
        requests.get("http://127.0.0.1:"+str(self.port))
