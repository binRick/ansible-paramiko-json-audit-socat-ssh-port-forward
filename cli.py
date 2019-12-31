#!/usr/bin/env python
import os
import socket
import select
import sys
import threading, sys, json, traceback, psutil, subprocess, getpass, time
from optparse import OptionParser

import paramiko

SSH_PORT = 22
DEFAULT_PORT = 4000

g_verbose = True

class __socat(threading.Thread):
  def __init__(self, client):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.client = client
  def run(self):
    cmd = 'socat -u FILE:/tmp/6c1bf75e-0733-4738-b552-a1118e12c61e/audit.json,ignoreeof,seek-end tcp:127.0.0.1:49552'
    time.sleep(2.0)
    exec_tunnel(self.client, cmd)


class __play(threading.Thread):
  def __init__(self, client):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.client = client
  def run(self):
    cmd = './delegatedServer-31472.sh'
    time.sleep(5.0)
    exec_tunnel(self.client, cmd)

class __ls(threading.Thread):
  def __init__(self, client):
    threading.Thread.__init__(self)
    self.kill_received = False
    self.client = client
  def run(self):
    cmd = 'ls'
    exec_tunnel(self.client, cmd)

class __localSocat(threading.Thread):
  def __init__(self):
    threading.Thread.__init__(self)
    self.kill_received = False
  def run(self):
    cmd = 'socat -u TCP4-LISTEN:49225,reuseaddr CREATE:/tmp/6c1bf75e-0733-4738-b552-a1118e12c61e/audit.json,perm=0640'
    cwd = '/'
    env = os.environ.copy()
    time.sleep(2.0)
    proc = subprocess.Popen(cmd.split(' '),stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env, shell=False)
    stdout, stderr = proc.communicate()
    exit_code = proc.exit_code

def handler(chan, host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        verbose("Forwarding request to %s:%d failed: %r" % (host, port, e))
        return

    verbose(
        "Connected!  Tunnel open %r -> %r -> %r"
        % (chan.origin_addr, chan.getpeername(), (host, port))
    )
    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()
    verbose("Tunnel closed from %r" % (chan.origin_addr,))


def exec_tunnel(client,cmd):
    print('et.........')
    stdin, stdout, stderr = client.exec_command(cmd);
    for line in stdout:
        print('... ' + line.strip('\n'))

def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    transport.request_port_forward("", server_port)
    while True:
#    if True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        thr = threading.Thread(
            target=handler, args=(chan, remote_host, remote_port)
        )
        thr.setDaemon(True)
        thr.start()


def verbose(s):
    if g_verbose:
        print(s)


HELP = """\
Set up a reverse forwarding tunnel across an SSH server, using paramiko. A
port on the SSH server (given with -p) is forwarded across an SSH session
back to the local machine, and out to a remote site reachable from this
network. This is similar to the openssh -R option.
"""


def get_host_port(spec, default_port):
    "parse 'hostname:22' into a host and port, with the port optional"
    args = (spec.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def parse_options():
    global g_verbose

    parser = OptionParser(
        usage="usage: %prog [options] <ssh-server>[:<server-port>]",
        version="%prog 1.0",
        description=HELP,
    )
    parser.add_option(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        default=True,
        help="squelch all informational output",
    )
    parser.add_option(
        "-p",
        "--remote-port",
        action="store",
        type="int",
        dest="port",
        default=DEFAULT_PORT,
        help="port on server to forward (default: %d)" % DEFAULT_PORT,
    )
    parser.add_option(
        "-u",
        "--user",
        action="store",
        type="string",
        dest="user",
        default=getpass.getuser(),
        help="username for SSH authentication (default: %s)"
        % getpass.getuser(),
    )
    parser.add_option(
        "-K",
        "--key",
        action="store",
        type="string",
        dest="keyfile",
        default=None,
        help="private key file to use for SSH authentication",
    )
    parser.add_option(
        "",
        "--no-key",
        action="store_false",
        dest="look_for_keys",
        default=True,
        help="don't look for or use a private key file",
    )
    parser.add_option(
        "-P",
        "--password",
        action="store_true",
        dest="readpass",
        default=False,
        help="read password (for key or password auth) from stdin",
    )
    parser.add_option(
        "-r",
        "--remote",
        action="store",
        type="string",
        dest="remote",
        default=None,
        metavar="host:port",
        help="remote host and port to forward to",
    )
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error("Incorrect number of arguments.")
    if options.remote is None:
        parser.error("Remote address required (-r).")

    g_verbose = options.verbose
    server_host, server_port = get_host_port(args[0], SSH_PORT)
    remote_host, remote_port = get_host_port(options.remote, SSH_PORT)
    return options, (server_host, server_port), (remote_host, remote_port)


def main():
    options, server, remote = parse_options()

    password = None
    if options.readpass:
        password = getpass.getpass("Enter SSH password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose("Connecting to ssh host %s:%d ..." % (server[0], server[1]))
    try:
        client.connect(
            server[0],
            server[1],
            username=options.user,
            key_filename=options.keyfile,
            look_for_keys=options.look_for_keys,
            password=password,
        )
    except Exception as e:
        print("*** Failed to connect to %s:%d: %r" % (server[0], server[1], e))
        sys.exit(1)

    verbose(
        "Now forwarding remote port %d to %s:%d ..."
        % (options.port, remote[0], remote[1])
    )

    try:
        if True:

            localSocat = __localSocat()
            localSocat.daemon = True
            localSocat.start()

            agent = __socat(client)
            agent.daemon = True
            agent.start()

            if True:
                play = __play(client)
                play.daemon = True
                play.start()


            ls = __ls(client)
            ls.daemon = True
            ls.start()


            reverse_forward_tunnel(
                options.port, remote[0], remote[1], client.get_transport()
            )

    


            reverse_forward_tunnel(
                options.port, remote[0], remote[1], client.get_transport()
            )

        else:
            reverse_forward_tunnel(
                options.port, remote[0], remote[1], client.get_transport()
            )
    except KeyboardInterrupt:
        print("C-c: Port forwarding stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
