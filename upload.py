#!/usr/bin/env python3
"""
Program allows to upload files to server. It supports HTTPS and runs HTTP server with
redirect response to HTTPS, so, short URL can be used to upload files through Internet.
"""

VERSION = '0.1 (Apr 10, 2021)'
BIND_ADDERSS = '0.0.0.0'    # servers listen on this ip
HTTP_PORT  = 8080           # http port,  used on local machine
HTTPS_PORT = 4443           # https port, used on local machine
EX_HTTP_PORT  = 80          # http port,  used on router
EX_HTTPS_PORT = 443         # https port, used on route
MAX_FILES  = 1000           # max attempts for file suffix
TIMEOUT = 10                # timeout for http (redirect) server connection
ROUTER_IP = '192.168.10.1'
ROUTER_TUN_IP = '10.0.0.1'
TUNNEL_NAME = 'tun0'
SSH_PORT = 61986
SSH_USER = 'root'

cert_path = '/etc/stunnel/cert.pem' # '/etc/stunnle/fullchain.pem' for 'old' wget
key_path =  '/etc/stunnel/key.pem'


import argparse
import threading
import sys
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler
import email.parser
import email.policy
import os.path
import time
import netifaces as ni
import paramiko
import socket           # for socket.timeout (in paramiko)


HTML = \
"""
<!DOCTYPE html>
<html>
 <head>
  <meta charset="utf-8">
  <title>Отправка файла на сервер</title>
 </head>
 <body>
  <form enctype="multipart/form-data" method="post">
   <p><input type="file" name="f" multiple>
   <input type="submit" value="Отправить"></p>
  </form> 
 </body>
</html>
"""

#################
### FUNCTIONS ###
#################

def save_file(fname, fcontent):
# save uploaded file

  # check whether file with same name exists
  test_name = os.path.join(dir_name, fname)
  for i in range (1, MAX_FILES + 1):
    if not os.path.isfile(test_name):
        f = open(test_name, "wb")
        f.write(fcontent)
        f.close
        break
    else:   # if file exist add '(n)' suffix to the end of file name
        newname = ''
        for ii, nn in enumerate(fname.rsplit('.',1)):
            if ii == 0:
                nn = nn + "(" + str(i) + ")" + "."
            newname += nn

        # and try again for MAX_FILES times
        test_name = os.path.join(dir_name, newname)


def sigint_handler(signal, frame):
# handle Ctrl-C 
    print("\nInterrupted")
    program_termination()
    sys.exit(0)     # Never executed

def program_termination():
# last cleaning
    # stop http server if launched in separate thread
    if not args.no_ssl and not args.no_http:
        httpd_redirect.shutdown()
        httpd_redirect.server_close()

    # close ports
    if not args.local:
        forward_ports('close')

    sys.exit(0)


def forward_ports(action):
    router = ROUTER_IP
    ssh_port = SSH_PORT
    ssh_user = SSH_USER
    # get default gateway interface name
    if_name = ni.gateways()['default'][ni.AF_INET][1]

    # if vpn activated, use it
    if TUNNEL_NAME in ni.interfaces():
        router = ROUTER_TUN_IP # change router ip to it's ip in tunnel network
        if_name = TUNNEL_NAME
    if not if_name:
        print('Error: no default network interface')
        program_termination()
    # get ip address of default gateway interface
    local_addr = ni.ifaddresses(if_name)[ni.AF_INET][0]['addr']

    if not args.quiet:
        if action == 'open':
            print('Trying to apply forward rules...')
        if action == 'close':
            print('Trying to delete forward rules...')

    # connect to router via ssh
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=router, username=ssh_user, port=ssh_port, timeout=5)
    except socket.timeout:
        print(f"Error: can't connect via ssh to server '{router}'", file=sys.stderr)
        sys.exit(1)

    if action == 'open':
        a = 'I'
    else:
        a = 'D'

    # forward ports (or delete previous forwad rules)
    if not args.no_http:    # forward http port if otherwise specified
        cmd = f'iptables -t nat -{a} PREROUTING -i eth0.2 -p tcp --dport {EX_HTTP_PORT} -j DNAT --to-destination {local_addr}:{HTTP_PORT}'
        stdin, stdout, stderr = client.exec_command(cmd)
        data = stdout.read() + stderr.read()
        if len(data):       # empty response is sign of success
            print(f"Error when apply rule ({cmd}) server return:", file=sys.stderr)
            print(data.decode('utf-8'), file=sys.stderr)
        else:
            if not args.quiet:
                print(cmd)
    #print(data.decode('utf-8'))
    if not args.no_ssl:     # forward https port if otherwise is specified
        cmd = f'iptables -t nat -{a} PREROUTING -i eth0.2 -p tcp --dport {EX_HTTPS_PORT} -j DNAT --to-destination {local_addr}:{HTTPS_PORT}'
        stdin, stdout, stderr = client.exec_command(cmd)
        data = stdout.read() + stderr.read()
        if len(data):       # empty response is sign of success
            print(f"Error when apply rule ({cmd}) server return:", file=sys.stderr)
            print(data.decode('utf-8'), file=sys.stderr)
        else:
            if not args.quiet:
                print(cmd)

    # on close (delete forward rules) make sure that no rules left with specified ports
    if action == 'close':
        cmd = f"iptables-save | grep -E '{HTTP_PORT}|{HTTPS_PORT}'"
        stdin, stdout, stderr = client.exec_command(cmd)
        data = stdout.read() + stderr.read()
        if  len(data):      # empty response is sign of succes
            print("Error: can't delete forward rules!!!", file=sys.stderr)
    client.close()
    # end port forward


#####################
### HTTP REDERECT ###
#####################

# http server with redirect (302) response
# This allows to use simple link, e.g. 'kuch.in' without 'https://...'

class server_http_redirect(threading.Thread):
    def __init__(self):
        super().__init__()

    class S(BaseHTTPRequestHandler):

        # set timeout for connection
        def setup(self):
            super().setup()
            self.request.settimeout(TIMEOUT)

        def _log(self, resp_code):
            client_ip, client_port = self.client_address
            # conditional print 
            if resp_code == 200:
                resp_str = 'OK'
            if resp_code == 302:
                resp_str = 'Found'
            if resp_code == 403:
                resp_str = 'Forbiddne'
            if resp_code == 404:
                resp_str = 'Not Found'
            if not args.quiet:
                print(f'{client_ip}:{client_port} - [{time.ctime()}] "GET {self.path} {self.request_version}" - {resp_code} {resp_str}')
            return

        def _html(self, title, message):
            content = "<html><head><title>" + title + "</title></head><body>" + message + "</body></html>"
            return content.encode("utf-8")

        def _set_headers_302(self):
            host = self.headers['Host']
            if host:
                host = host.split(':')[0]
            else:
                host = HOST
            self.wfile.write(b'HTTP/1.1 302 Found\r\n')
            self.wfile.write(b'Content-Length: 0\r\n')
            self.wfile.write(f'Location: https://{host}:{EX_HTTPS_PORT}{self.path}'.encode('utf-8'))
            self.wfile.write(b'\r\n\r\n')

        def _set_headers_403(self):
            self.wfile.write(b'HTTP/1.1 403 Forbidden\r\n')
            self.wfile.write(b'Content-type: text/html\r\n\r\n')


        def do_GET(self):
            # check whether client ip is in list of allowed (if feature is specified)
            client_ip, client_port = self.client_address
            # send 'found' if in list (or feature not used)
            if not args.ip or client_ip in args.ip:
                self._set_headers_302()
                self._log(302)
            else:
                # send 'forbidden' otherwise
                self._set_headers_403()
                self.wfile.write(self._html('Forbiddne', '<h1>Forbidden!</h1>'))
                self._log(403)

    def run(self):
        # use global 'httpd_redirect' variable to stop server in main thread
        global httpd_redirect
        httpd_redirect = HTTPServer( (BIND_ADDERSS, HTTP_PORT), self.S)
        httpd_redirect.serve_forever()

###################
### MAIN SERVER ###
###################

class S(BaseHTTPRequestHandler):
    def _html(self, message):
        content = "<html><title>Upload files</title><body>" + message + "</body></html>"
        return content.encode("utf8")

    def _set_headers_200(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def _set_headers_403(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def _set_headers_404(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if self.path != "/":        # only '/' path is allowed
          self._set_headers_404()   # send 'not found' otherwise
          self.wfile.write(self._html("Not Found!"))
        else:       # send '200 OK' if '/' is requested
          self._set_headers_200()
          self.wfile.write(self._html(HTML))

    def do_POST(self):
        # check whether client ip in list of allowed addersses
        client_ip, client_port = self.client_address
        if args.ip and client_ip not in args.ip:
            self._set_headers_403()
            self.wfile.write(self._html('<h1>Forbidden!</h1>'))
            return
        # end check ip
        self._set_headers_200() # set headers here, because http.server will print logs
                                # and we want them before program 'hangs' on parsing attachment
        # prepare 'data' to email.parser: headers + attachment
        content_lenght = int (self.headers['Content-Length'])
        data = ''
        data = data + 'Content-Length: ' + self.headers['Content-Length']
        data = data + '\nContent-Type: ' + self.headers['Content-Type']
        data = data + '\n\n'
        datab = bytes(data, 'utf-8')
        datab += self.rfile.read(content_lenght)
        # use email.policy.SMTPUTF8 to parse russian letters
        msg = email.parser.BytesParser(policy=email.policy.SMTPUTF8).parsebytes(datab)
        for part in msg.get_payload():
            fname = part.get_param('filename', header='content-disposition')
            fcontent = part.get_payload(decode=True)
            save_file(fname, fcontent)  # send parced data to function that will save file
            if not args.quiet:
                print(f"'{fname}' was saved")

        # answer to client and exit
        self.wfile.write(self._html("File(s) successfully uploaded!"))
        global RUNNING
        RUNNING = False
        if not args.quiet:
            print("Normal termination")


################################
### MAIN PROGRAM STARTS HERE ###
################################


#######################
### ARGUMETS PARSER ###
#######################

description='Server for uploading files'
parser = argparse.ArgumentParser(description=description)
parser.add_argument("-v", "--version", help="show version and exit", version=VERSION, action="version")
parser.add_argument("-q", "--quiet",   help="suppress all output except errors",      action='store_true')
parser.add_argument("-l", "--local",   help="share locally (don't forward ports)",     action="store_true")
parser.add_argument("-d", "--dir",     help="directory to store uploaded files")

group = parser.add_mutually_exclusive_group()
group.add_argument("-n", "--no-ssl",   help="do not use https, only http",            action="store_true")
group.add_argument("--no-http",        help="do not use http, only https",            action="store_true")
parser.add_argument("--ip", nargs="+", help="accept connections only from specified ip(s)",  metavar='IP')

args = parser.parse_args()

### END ARGUMENTS PARSER ###

# if share localy, HOST = local_ip
if args.local:
    # get default gateway interface
    if_name = ni.gateways()['default'][ni.AF_INET][1]
    # and get ip of this interface
    local_addr = ni.ifaddresses(if_name)[ni.AF_INET][0]['addr']
    HOST = local_addr           # change HOST to local ip, needed to redirect 'Location'
    EX_HTTPS_PORT = HTTPS_PORT  # needed for redirect 'Location'

if args.dir:
    # work on directory where files will be stored
    # If not specified, directory where program was run will be used
    dir_name = args.dir
    if not os.path.exists(dir_name):
        print(f"Error: directory '{dir_name}' doesn't exist", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(dir_name):
        print(f"Error: '{dir_name}' is not a directory", file=sys.stderr)
        sys.exit(2)
else:
    dir_name = ''   # means nothing for os.path.join()


# handling Ctrl-C
signal.signal(signal.SIGINT, sigint_handler)

if not args.no_ssl:
    import ssl
    # Start http server with 302 response in separate thread
    if not args.no_http:
        http_redirect_thread = server_http_redirect()
        http_redirect_thread.start()
        if not args.quiet:
            print(f'Server is listening on {BIND_ADDERSS}:{HTTP_PORT}')

    # now start main server
    httpsd = HTTPServer( (BIND_ADDERSS, HTTPS_PORT), S)
    if not args.quiet:
        print(f'Server is listening on {BIND_ADDERSS}:{HTTPS_PORT}')
    # wrap socket into ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    httpsd.socket = context.wrap_socket (httpsd.socket, server_side=True)
else:
    # if we don't use ssl, run server without ssl wraper (but we still call in 'httpSd')
    httpsd = HTTPServer( (BIND_ADDERSS, HTTP_PORT), S)
    if not args.quiet:
        print(f'Server is listening on {BIND_ADDERSS}:{HTTP_PORT}')

# port forwarding on router
if not args.local:
    forward_ports('open')

RUNNING = True      # main server will rewrite RUNNING after handling POST request and saving files
while RUNNING:
    httpsd.handle_request()

program_termination()   # make last cleaning and exit
# try:                  # alternative way to start server
#     httpd.serve_forever()
# except KeyboardInterrupt:
#     pass
# httpd.server_close()
### END MAIN ###
