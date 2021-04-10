#!/usr/bin/env python3
'''
Program for sharing files over LAN or internet.
It can open ports on router via ssh and redirect connections
HTTPS can be activated through 'stunnel'
'''


###################
##### GLOBALS #####
###################

VERSION = '0.1 (Apr 10, 2021)'
BIND_ADDERSS = '0.0.0.0'        # address, where servers are listening
HTTP_PORT = 8080                # http port of local redirect server. Port > 1000 to prevent 'sudo'
HTTPS_PORT = 4443               # https (http if --no-ssl) of main local server
HOST = 'kuch.in'                # host to use, when not specified in headers
#HOST = '192.168.10.102'    # take form headers if present
TIMEOUT = 10                # response timeout for redirect server (process hangs without it)
SSH_TIMEOUT = 5             # timeout to connect to router via ssh
EX_HTTP_PORT = 80           # External http port (on router) to forward HTTP_PORT
EX_HTTPS_PORT = 443         # External https port (on router) to forward to HTTPS_PORT
AUTH_LEN = 12               # Length of auth string in url
cert_path = '/etc/stunnel/fullchain.pem'    # with cert.pen works fine, but not with 'wget'
key_path =  '/etc/stunnel/key.pem'

### END GLOBALS ###


###############
### IMPORTS ###
###############

import argparse
import threading                    # Http server for redirect will be executed in separate thread
from http.server import HTTPServer, BaseHTTPRequestHandler  # for both: http redirect and main servers
import sys                          # sys.exit, sys.stderr, etc.
import os                           # for os.path.basename(), os.path.isfile(), os.listdir(), etc.
import time                         # 'time.ctime' for log
import signal                       # To catch Ctrl-C signal
from urllib.parse import unquote    # To decode url with '%' sign (russian letters)
from progress.bar import Bar
# zip and ssl are imported below if it is needed
import random                   # for auth string generation
import string                   # for auth string generation
import netifaces as ni          # to get ip adderss and default gateway
import paramiko                 # to communicate with router via ssh
import socket                   # for socket.timeout

### END IMPORTS ###


#################
### FUNCTIONS ###
#################

def sigint_handler(signal, frame):
# SIGINT handler
    if not args.quiet:
        print("\nInterrupted")
    else:
        print('')
    program_termination()

def program_termination():
# stop http server if launched in separate thread
    if not args.no_ssl and not args.no_http:
        httpd_redirect.shutdown()
        httpd_redirect.server_close()

    # close ports in a router
    if not args.local:
        forward_ports('close')

    # If we created zip archive, delete it
    if args.zip:
        if not args.quiet:
            print(f"Deleting zip archive at '{zip_name}'")
        os.system(f'rm {zip_name}')
    sys.exit(0)

def gen_files(files):
# generator produces file names walking through directories
# we need it only if --html is not specified
    for f in files:
        if os.path.isfile(f):
            yield f
        elif os.path.isdir(f):
            for dir, subdirs, com_files in os.walk(f):
                for ff in com_files:
                    yield os.path.join(dir, ff)

def getzipfile(files):
# creates zip archive from files listed in 'files' and returns it's name
    # define auxiliary function:
    # it was taken from zipfile module
    def addToZip(zf, path, zippath):
        if os.path.isfile(path):
            zf.write(path, zippath, ZIP_DEFLATED)
        elif os.path.isdir(path):
            if zippath:
                zf.write(path, zippath)
            for nm in sorted(os.listdir(path)):
                addToZip(zf, os.path.join(path, nm), os.path.join(zippath, nm))


    from zipfile import ZipFile, ZIP_DEFLATED
    zip_name = '/tmp/archive.zip'

    # if file with this name already exists, then add sufix (0000 - 9999) to it's name
    if os.path.exists(zip_name):
        for i in range(10000):
            zip_name = f'/tmp/archive_{i:04}.zip'
            if not os.path.exists(zip_name):
                break
        else:
            print(f"Error: can't create zip archive", file=sys.stderr)
            sys.exit(1)

    with ZipFile(zip_name, 'w') as zf:
        for path in files:
            # don't include directories if 'no_dirs'
            if os.path.isdir(path) and args.no_dirs:
                continue
            zippath = os.path.basename(path)
            if not zippath:
                zippath = os.path.basename(os.path.dirname(path))
            if zippath in ('', os.curdir, os.pardir):
                zippath = ''
            addToZip(zf, path, zippath)

    return zip_name
    # end getzipfile


def get_file_list(path):
# creates html code with list of files
    result = f''
    if args.auth:
        a = auth
    else:
        a = ''
    if html_mode == 1:      # files  are linked by numbers they appeare in args.files
        for file in sorted(args.files):
            # skeep hidden files unless opposite directly specified
            if os.path.basename(file)[0] == '.' and not args.show_hidden:
                continue
            result += f'<a href="/{os.path.join(a, str(args.files.index(file)))}">{os.path.basename(file)}</a><br>'

    else:   # html_mode == 2: allows to warlk through inside one specified directory
            # files are linked by they names
        if path != '/':
            result += f'<a href="..">..</a><br>'    # add 'back' link anywhere except main page
        if path[0] == '/':          # remove leading '/' in path if presents
            path = path[1:]         # if don't do that, join will fail
        abs_path = os.path.join(dir_name, path)
        file_list = os.listdir(abs_path)
        for file in sorted(file_list):
            # skeep hidden files unless opposite directly specified
            if os.path.basename(file)[0] == '.' and not args.show_hidden:
                continue
            if os.path.isdir(abs_path + file):
                # mark directories with '/' suffix
                result += f'<a href="/{os.path.join(a, path, file)}/">{file}/</a><br>'
            else:
                result += f'<a href="/{os.path.join(a, path, file)}">{file}</a><br>'
    return result
    # end create file list

def forward_ports(action):
# forward ports on router to local http-redirect and main servers
    # get default gateway interface name
    if_name = ni.gateways()['default'][ni.AF_INET][1]

    # if vpn activated, use it
    if 'tun0' in ni.interfaces():
        router = '10.0.0.1'     # not needed actually, because '192.168.10.1' is routed via vpn
        if_name = 'tun0'
    if not if_name:
        print('Error: no default network interface')
        program_termination()   # servers are running for that moment, we need to stop them
    # get ip-adderess of default interface or tun0 interface
    local_addr = ni.ifaddresses(if_name)[ni.AF_INET][0]['addr'] 

    # connect to router via ssh
    router = '192.168.10.1'
    ssh_port = 61986
    ssh_user = 'root'

    if not args.quiet:
        if action == 'open':
            print('Trying to apply forward rules...')
        if action == 'close':
            print('Trying to delete forward rules...')

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=router, username=ssh_user, port=ssh_port, timeout=SSH_TIMEOUT)
    except socket.timeout:
        print(f"Error: can't connect via ssh to server '{router}'", file=sys.stderr)
        sys.exit(1)

    if action == 'open':
        a = 'I'
    else:
        a = 'D'

    if not args.no_http:
        cmd = f'iptables -t nat -{a} PREROUTING -i eth0.2 -p tcp --dport {EX_HTTP_PORT} -j DNAT --to-destination {local_addr}:{HTTP_PORT}'
        stdin, stdout, stderr = client.exec_command(cmd)
        data = stdout.read() + stderr.read()
        if len(data):   # silence is a sign of a successful operation 
            print(f"Error when applying rule ({cmd}); server return:", file=sys.stderr)
            print(data.decode('utf-8'), file=sys.stderr)
        else:
            if not args.quiet:
                print(cmd)

    if not args.no_ssl:
        cmd = f'iptables -t nat -{a} PREROUTING -i eth0.2 -p tcp --dport {EX_HTTPS_PORT} -j DNAT --to-destination {local_addr}:{HTTPS_PORT}'
        stdin, stdout, stderr = client.exec_command(cmd)
        data = stdout.read() + stderr.read()
        if len(data):   # silence is a sign of a successful operation
            print(f"Error when applying rule ({cmd}); server return:", file=sys.stderr)
            print(data.decode('utf-8'), file=sys.stderr)
        else:
            if not args.quiet:
                print(cmd)

    if action == 'close':
        # check whether no rules left in iptables
        cmd = f"iptables-save | grep -E '{HTTP_PORT}|{HTTPS_PORT}'"
        stdin, stdout, stderr = client.exec_command(cmd)
        data = stdout.read() + stderr.read()
        if  len(data):  # silence is a sign of a successful operation
            print("Error: can't delete forward rules!!!", file=sys.stderr)
    client.close()  # close ssh session

### END FUNCTIONS ###


#####################
### HTTP REDERECT ###
#####################

class server_http_redirect(threading.Thread):
# http server with redirect (302) answer. This allows to use simple link, e.g. 'kuch.in' without 'https://...'
    def __init__(self):
        super().__init__()

    class S(BaseHTTPRequestHandler):
        close_connection=True

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
            if host:    # split port number if present
                host = host.split(':')[0]
            else:
                host = HOST     # if 'Host' header is not specified by client, use default
            self.wfile.write(b'HTTP/1.1 302 Found\r\n')
            self.wfile.write(b'Content-Length: 0\r\n')
            # redirect to the same path, but with https protocol and to EX_HTTPS_PORT (last can be skipped,
            # when 443 port is used, but usefull otherwise and when --local specified (4443 is used by default)
            self.wfile.write(f'Location: https://{host}:{EX_HTTPS_PORT}{self.path}'.encode('utf-8'))
            self.wfile.write(b'\r\n\r\n')

        def _set_headers_403(self):
            self.wfile.write(b'HTTP/1.1 403 Forbidden\r\n')
            self.wfile.write(b'Content-type: text/html\r\n\r\n')


        def do_GET(self):
            # check whether client ip is in list of allowed addersses (if this feature is activated)
            client_ip, client_port = self.client_address
            if not args.ip or client_ip in args.ip:
                # redirect if evrything is OK
                self._set_headers_302()
                self._log(302)
            else:
                self._set_headers_403()
                self.wfile.write(self._html('Forbidden', '<h1>Forbidden!</h1>'))
                self._log(403)

    def run(self):
        # run http-redirect server in separate thread
        global httpd_redirect   # we need it to stop server in program_termination() function
        httpd_redirect = HTTPServer( (BIND_ADDERSS, HTTP_PORT), self.S)
        httpd_redirect.serve_forever()

### END HTTP REDIRECT ###


###################
### MAIN SERVER ###
###################

class S(BaseHTTPRequestHandler):

    def _log(self, resp_code):
        client_ip, client_port = self.client_address
        # conditional print 
        if resp_code == 200:
            resp_str = 'OK'
        if resp_code == 403:
            resp_str = 'Forbidden'
        if resp_code == 404:
            resp_str = 'Not Found'
        if not args.quiet:
            print(f'{client_ip}:{client_port} - [{time.ctime()}] "GET {self.path} {self.request_version}" - {resp_code} {resp_str}')
        return

    def _html(self, title, message):
        content = "<!DOCTYPE html><html><head><title>" + title + '</title></head><body style="margin:20px ;padding:0">' + message + "</body></html>"
        return content.encode("utf-8")

    def _set_headers_200(self):
        self.wfile.write(b'HTTP/1.1 200 OK\r\n')
        self.wfile.write(b'Content-type: text/html;charset=UTF-8\r\n\r\n')

    def _set_headers_200_file(self, fname):
        self.wfile.write(b'HTTP/1.1 200 OK\r\n')
        self.wfile.write(f'Content-Disposition: attachment; filename={os.path.basename(fname)}\r\n'.encode('utf-8'))
        self.wfile.write(b'Content-Type: application/octet-stream\r\n')
        self.wfile.write(f'Content-Length: {os.path.getsize(fname)}\r\n'.encode('utf-8'))
        self.wfile.write(b'Connection: close\r\n\r\n')

    def _set_headers_404(self):
        self.wfile.write(b'HTTP/1.1 404 Not Found\r\n')
        self.wfile.write(b'Content-type: text/html\r\n\r\n')

    def _set_headers_403(self):
        self.wfile.write(b'HTTP/1.1 403 Forbidden\r\n')
        self.wfile.write(b'Content-type: text/html\r\n\r\n')

    def _send_file(self, fname):
        # get size of terminal to show status bar
        rows, columns = [int(i) for i in os.popen('stty size', 'r').read().split()]
        bar = Bar(suffix = '%(index)d/%(max)d%%', width = columns - 12, bar_prefix='[', bar_suffix=']')
        file_size = os.path.getsize(fname)
        # read file by chunks
        chunk = file_size//100
        # if file too small read it by one action
        if chunk == 0:
            chunk = file_size

        self._set_headers_200_file(fname)
        if not args.quiet:
            print(f"File '{fname}' downloading:")
        with open(fname, 'rb') as f:
            while self.wfile.write(f.read(chunk)):
                if not args.quiet:
                    bar.next()
            if not args.quiet and bar.index !=100:
                # set status bar to 100% after reading
                bar.index = 99
                bar.next()
        bar.finish()

    def do_GET(self):
        # 'cur_file_name stores file name between GET responses
        # 'cur_file_name is used only if '--html' is not specified
        global cur_file_name

        client_ip, client_port = self.client_address
        # check whether client ip is in list of allowed addersses (if this feature is activated)
        if args.ip and client_ip not in args.ip:
            self._set_headers_403()
            self.wfile.write(self._html('Forbidden', '<h1>Forbidden!</h1>'))
            self._log(403)
            return
        # end check ip

        # check auth string at the begining of URL (if this feature is activated)
        if args.auth:
            l = self.path.split('/')
            a = l.pop(1)
            self.path = '/'.join(l)
            if self.path == '':
                self.path = '/'
            if not a == auth:
                self._set_headers_403()
                self.wfile.write(self._html('Forbidden', '<h1>Forbidden!</h1>'))
                self._log(403)
                return
        # end check auth

        # reject path with '..' (modern browsers do not allow it by their own)
        if '..' in self.path.split('/'):
            self._set_headers_404()
            self.wfile.write(self._html('Not found', '<h1>Not Found!</h1>'))
            self._log(404)
            return
        # decode special symbols (mainly russian letters)
        if '%' in self.path:
            self.path = unquote(self.path)

        # if html output used:
        # html_mode == 1: files are accessed by 'id' (number of file in args.files list), no directories
        # html_mode == 2: files are accessed by their names, directories are allowed
        if args.html and html_mode == 1:
            if self.path == '/':
                self._set_headers_200()
                self.wfile.write(self._html('File list', get_file_list(self.path)))
                self._log(200)
            else:
                file_index = self.path[1:]
                if file_index.isdigit():            # check whether we got digit
                    ind = int(file_index)
                    if 0 <= ind < len(args.files):  # check whether this digit is 'good'
                        file_name = args.files[ind]
                        self._log(200)
                        self._send_file(file_name)
                    else:                           # if digit > then number of filse we have
                        self._set_headers_404()     # send 'not found'
                        self.wfile.write(self._html('Not found', '<h1>Not found!</h1>'))
                        self._log(404)
                else:                           # if we got not digit
                    self._set_headers_404()     # send 'not found'
                    self.wfile.write(self._html('Not found', '<h1>Not found!</h1>'))
                    self._log(404)
            return 
        # html_mode == 2 (one directory was specified as 'files' in command line argument
        # it is possible to walk through this directory
        if args.html and html_mode == 2:
            full_path = dir_name + self.path
            if not os.path.exists(full_path):
                self._set_headers_404()
                self.wfile.write(self._html('Not found', '<h1>Not Found!</h1>'))
                self._log(404)
                return
            if os.path.isdir(full_path):
                self._set_headers_200()
                self.wfile.write(self._html('File list', get_file_list(self.path)))
                self._log(200)
            else:
                self._log(200)
                self._send_file(full_path)
            return
        # end html
        # code below is not executed if args.html specified (because of 'return' above)

        # send file and log
        # only following code is needed to be executed to send a file if args.html is not specified
        short_file_name = os.path.basename(cur_file_name)
        self._log(200)
        self._send_file(cur_file_name)
        # that is all we need to send a file without html =) 

        # get new file name
        if not args.html:   # if args.html specified we shuldn't be here actually
            try:
                cur_file_name = next(gf)
            except StopIteration:
                global RUNNING
                RUNNING = False

### END MAIN SERVER ###


 ################### 
###               ###
##  MAIN FUNCTION  ##
###               ###
 ################### 


#######################
### ARGUMETS PARSER ###
#######################

description= """Shares files and directories over Internet and LAN.
Supports ssl, html, zip, authentication, port forwarding and others functionality."""
parser = argparse.ArgumentParser(description=description)
parser.add_argument("-v", "--version",  help="show version and exit",      version=VERSION,   action="version")
parser.add_argument("files", nargs="+", help="file(s) and directory(ies) to share")
parser.add_argument("-q", "--quiet",    help="suppress all output except errors",             action='store_true')
parser.add_argument("-z", "--zip",      help="send all files as zip archive",                 action='store_true')
parser.add_argument("-m", "--html",     help="show html page with files to download",         action="store_true")
parser.add_argument("-l", "--local",    help="share locally (don't forward ports)",           action="store_true")

group1 = parser.add_mutually_exclusive_group()
group1.add_argument("-a", "--auth",     help="use random authentication string in URL",      action="store_true")
group1.add_argument("-p", "--path",     help="use additional path in URL, i.e. https://host/path")
                    
group2 = parser.add_mutually_exclusive_group()
group2.add_argument("-n", "--no-ssl",   help="do not use https, only http",                   action="store_true")
parser.add_argument("-o", "--open-only",help="don't run servers, only open ports",            action="store_true")
parser.add_argument("--http-port",      help="specify local http port",  metavar='    PORT',  type=int)
parser.add_argument("--https-port",     help="specify local https port",  metavar='   PORT',  type=int)
parser.add_argument("--ex-http-port",   help="specify external http port",  metavar=' PORT',  type=int)
parser.add_argument("--ex-https-port",  help="specify external https port",  metavar='PORT',  type=int)
group2.add_argument("--no-http",        help="do not use http, only https",                   action="store_true")
parser.add_argument("--no-dirs",        help="don't share directories, only ordinary files",  action='store_true')
parser.add_argument("--show-hidden",    help="show hidden files in html page",                action='store_true')
parser.add_argument("--ip", nargs="+",  help="accept connections only from specified ip(s)",  metavar='IP')


args = parser.parse_args()

# set ports if specified
if args.http_port:
    HTTP_PORT = args.http_port
if args.https_port:
    HTTPS_PORT = args.https_port
if args.ex_http_port:
    EX_HTTP_PORT = args.ex_http_port
if args.ex_https_port:
    EX_HTTPS_PORT = args.ex_https_port

# if only open ports needed:
if args.open_only:
    forward_ports('open')
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        if not args.quiet:
            print('\nInterrupted')
    forward_ports('close')
    sys.exit(0)

# Check whether 'no-dir' is specified and only one directory is shared
# If so, put all files from this directory to file list, because then all directories will be excluded

html_mode = 1                       # if single directory not specified, use html_mode == 1
if len(args.files) == 1 and os.path.isdir(args.files[0]):   # if only one directory specified
    dir_name = args.files[0]        # store dir. name to use in future
    if dir_name[-1] == '/':         # remove '/' suffix if present for futher use in 'dir_name + self.path'
        dir_name = dir_name[:-1]
    # put all files from specified directory to args.files
    args.files = [os.path.join(dir_name, f) for f in os.listdir(args.files[0])]
    html_mode = 2   # if directory specified, use html_mode == 2 (1 otherwise, see above)

# exclude directories from file list if option is specified
if args.no_dirs:
    new_files = []          # without storing in a separate list seems not work properly (???)
    html_mode = 1           # set html_mode to 1, because we don't have directories to share
    for f in args.files:
        if os.path.isfile(f):
            new_files.append(f)
    args.files = new_files  # set args.files to store only files not directories

# if we want to share all files as zip archive
# we need to create zip archive and put only it's name to 'args.files'
if args.zip:
    if not args.quiet:
        print('Preparing zip archinve...')
    zip_name = getzipfile(args.files)
    args.files = [zip_name]     # now args.files stores only archive name
    if not args.quiet:
        print(f"Zip archive is ready at '{zip_name}'")

# check whether all files exist
for f in args.files:
    if not os.path.exists(f):
        print(f"Error: file '{f}' does't exists", file=sys.stderr)
        sys.exit(1)

if args.html:
    # we can't walk through folders which are in differnt places in file system
    for f in args.files:
        if os.path.isdir(f) and html_mode == 1:
            print("Error: files and directories can't be mixed, when --html specified. Specify only one directory and/or use --no-dirs parameter instead.", file=sys.stderr)
            sys.exit(1)

# There can be the case of empty folder passed as single parameter
# So we use 'try'  even at first call of next(gf)
# make generator for file names
gf = gen_files(args.files)

try:
    cur_file_name = next(gf)
except StopIteration:
    print(f"Error: no files to share. Check 'files' comand line argument!")
    sys.exit(2)

# At this point args.files can't be empty, check it as a precaution
assert args.files

if args.auth:
    # generate random lowcase string of length AUTH_LEN to use it as secret
    auth=''.join(random.choices(string.ascii_lowercase, k=AUTH_LEN))
    if not args.no_ssl:         # turn off http-redirect to prevent auth string sending in a plain text,
        args.no_http = True     # until otherwise specified
else:                   # use 'path' only if not 'auth' specified
    if args.path:
        auth = args.path
        args.auth = True

# if share localy, we change HOST = local_ip to right redirect path and to show correct share link
if args.local:
    if_name = ni.gateways()['default'][ni.AF_INET][1]           # default gateway interface
    local_addr = ni.ifaddresses(if_name)[ni.AF_INET][0]['addr'] # adderss of this interface
    HOST = local_addr 
    EX_HTTPS_PORT = HTTPS_PORT      # needed in redirect 'Location' path

# Print shared link:
if not args.quiet:
    print('Link to share files:')
if args.no_http:
    if args.auth:
        print(f'https://{HOST}/{auth}')
    else:
        if not args.quiet:
            print(f'https://{HOST}')
else:
    if not args.quiet:
        if args.auth:
            print(f'{HOST}/{auth}')
        else:
            print(f'{HOST}')

### END ARGUMENTS PARSER ###

# Catching Ctrl-C
signal.signal(signal.SIGINT, sigint_handler)

#####################
### START SERVERS ###
#####################

if not args.no_ssl:
    import ssl
    # Start http server with 302 response in separate thread if not suppressed by 'no-http'
    if not args.no_http:
        http_redirect_thread = server_http_redirect()
        http_redirect_thread.start()
        if not args.quiet:
            print(f'Server is listening on {BIND_ADDERSS}:{HTTP_PORT}')

    # now start main server
    httpsd = HTTPServer( (BIND_ADDERSS, HTTPS_PORT), S)
    if not args.quiet:
        print(f'Server is listening on {BIND_ADDERSS}:{HTTPS_PORT}')
    # wrap connection to ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    httpsd.socket = context.wrap_socket (httpsd.socket, server_side=True)
else:
    # if 'no-ssl' specified start main server without ssl wrap
    #(we still call it httpSd despit it is http now)
    httpsd = HTTPServer( (BIND_ADDERSS, HTTP_PORT), S)
    if not args.quiet:
        print(f'Server is listening on {BIND_ADDERSS}:{HTTP_PORT}')

### END START SERVERS ###

# deprecated variant of wrapper:
#httpsd.socket = ssl.wrap_socket (httpsd.socket, certfile='cert.pem', keyfile='key.pem', server_side=True)

# port forwarding on router
if not args.local:
    forward_ports('open')

RUNNING = True  # will be set to False in main server if files are exhausted
while RUNNING:
    httpsd.handle_request()
#httpsd.serve_forever()     # we use 'handle_request()' to stop server when files are exhausted

program_termination()       # terminate program properly: stop http server, delete zip and so on

### END MAIN ###
