#
# This file contains all of the modules based on ssh_base and are used for
# actions that requites remote access to a remote server
#

import base
import getpass
import paramiko
import socket
import errno
import sys
import time
import os
import meta
import json
import subprocess
import signal

#
# Custom exception
#

class ERROR_exception(Exception):
        def __init__(self, msg):
            self.msg = msg

#
# ssh_check module: repeatedly check the ssh connectivity to host until it comes up.
# require "pip install paramiko"
#

class ssh_check(base.remote_base):
    description = "checking ssh connectivity to host"

    def __init__(self, host, user, password):
        super(ssh_check, self).__init__("ss_check", "n/a")
        self.host = host
        self.user = user
        self.password = password
        
    def main(self):
        message = []
        return_dict = {}

        devnull = open(os.devnull, 'w')
        start = time.time()
        client = paramiko.SSHClient()
        max_span = 20

        try:

            while True:
                try:
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    subprocess.call(["ssh-keygen", "-R", self.ip], stdout=devnull, stderr=devnull)
                    client.connect(self.host, username=self.user, password=self.password, 
                                   timeout=max_span, banner_timeout=max_span)
                    client.close()
                    
                except socket.error:
                    pass
                
                else:
                    message.append("connection established")
                    break
        
        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, 
                paramiko.SSHException) as e:
            
            return_dict["success"] = "False"
            meta_dict = meta.meta_header()
            return_dict["error"] = str(e)
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:
            return_dict["success"] = "True"
            meta_dict = meta.meta_header()
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)


#
# upload_script module: upload, (run and remove) a script from local to remote host
#
class upload_script(base.remote_base):
    description = 'upload, run and remove a script from local to remote host'

    # Supported file types dictionary, expand when necessary
    types = {"py": "pyhon", "sh": "sh"}

    def __init__(self, host, user, password, run, delete, local, remote):
        super(upload_script, self).__init__("upload_script", "n/a")
        self.remote = remote
        self.local = local
        self.run = run
        self.delete = delete
        self.host = host
        self.user = user
        self.password = password
        if self.run:
            self.interpreter = run_script.types[self.script_type]

    def main(self):
        message = []
        return_dict = {}
        client = paramiko.SSHClient()
        try:
            # Validate the local file
            if not os.path.isfile(self.local):
                raise ERROR_exception("The local file is not valid")

            # Connect to remote host
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            # Setup sftp connection and transmit this script
            sftp = client.open_sftp()
            sftp.put(self.local, self.remote) 
            sftp.close()
            message.append("upladded " + self.local + " to " + self.remote)

            # Run the script remotely and collect output
            # SSHClient.exec_command() returns the type (stdin, stdout, stderr)
            if self.run:
                (stdin, stdout, stderr) = client.exec_command(self.interpreter + " " + self.remote)
                error = stderr.read()
                out_put = stdout.read()

                if error or stdout.channel.recv_exit_status():
                    raise ERROR_exception(error)
                else:
                    message.append(out_put)

            #removing the file on the remote host
            if self.delete:
                client.exec_command("rm -rf " + self.remote) 
                message.append("removed" + self.remote)
            
            #close the pipe
            client.close()

        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, 
                paramiko.SSHException, IOError, ERROR_exception) as e:
            
            return_dict["success"] = "False"
            meta_dict = meta.meta_header()
            if hasattr(e, "msg"):
                return_dict["error"] = e.msg
            else:
                return_dict["error"] = str(e)
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:
            return_dict["success"] = "True"
            meta_dict = meta.meta_header()
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)


#
# upload_files module: upload one or multiple files
#
class upload_files(base.remote_base):
    description = 'upload one or multiple files'

    def __init__(self, host, user, password, local_remote):
        super(upload_files, self).__init__("upload_script", "n/a")
        self.host = host
        self.user = user
        self.password = password
        self.local_remote = local_remote

    def main(self):
        message = []
        return_dict = {}
        client = paramiko.SSHClient()

        try:
            # Validate input output paring
            if len(self.local_remote["local"]) != len(self.local_remote["remote"]):
                raise ERROR_exception("number of local files given doesn't match the remote locations")

            # Validate the local file
            for file in self.local_remote["local"]:
                if not os.path.isfile(file):
                    raise ERROR_exception("The local file " + file +  " is not valid")

            # Connect to remote host
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            # Setup sftp connection and transmit this script
            sftp = client.open_sftp()

            for (local, remote) in zip(self.local_remote["local"], self.local_remote["remote"]):
                sftp.put(local, remote) 
                message.append("uploaded " + local + " to " + remote)

            sftp.close()

            #close the pipe
            client.close()

        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, 
                paramiko.SSHException, IOError, ERROR_exception) as e:
            
            return_dict["success"] = "False"
            meta_dict = meta.meta_header()
            if hasattr(e, "msg"):
                return_dict["error"] = e.msg
            else:
                return_dict["error"] = str(e)
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:
            return_dict["success"] = "True"
            meta_dict = meta.meta_header()
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)


#
# run_command module: run commands on a remote host
#
class run_command(base.remote_base):
    description = 'run a commands on the remote host'

    def __init__(self, host, user, password, *commands):
        super(run_command, self).__init__("run_command", "n/a")
        self.user = user
        self.host = host
        self.password = password
        self.commands = commands

    def main(self):
        return_dict = {}
        message = []
        result = []

        client = paramiko.SSHClient()
        try:
            # Connect to remote host
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            # load the ~/.profile before running commands nop, not for statseeker
            pre_command = ". ~/.profile;"
            
            # execute the given list of commands
            for command in self.commands:
                message.append("running " + command)
                command = pre_command + command
                (stdin, stdout, stderr) = client.exec_command(command, get_pty=True)
                error = stderr.read()
                out_put = stdout.read()

                if error or stdout.channel.recv_exit_status():
                    raise ERROR_exception(error)
                else:
                    result.append(out_put)

            #close the pipe
            client.close()

        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, 
                paramiko.SSHException, socket.error, ERROR_exception) as e:

            return_dict["success"] = "False"
            meta_dict = meta.meta_header()
            if hasattr(e, "msg"):
                return_dict["error"] = e.msg
            else:
                return_dict["error"] = str(e)
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:

            return_dict["success"] = "True"
            meta_dict = meta.meta_header()
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)

#
# add_route module: add route to statseekerbox, toggle for wether adding it permanently
#

class add_route(base.remote_base):
    description = "add permanent route to statseeker box"

    def __init__(self, host, password, perm, **net):
        super(add_route, self).__init__("add_route", "n/a")
        self.password = password
        self.user = "root"
        self.host = host
        self.perm = perm
        self.net = net
        
    def main(self):
        message = []
        return_dict = {}

        devnull = open(os.devnull, 'w')
        start = time.time()
        client = paramiko.SSHClient()
        max_span = 20

        try:
            if "route" not in self.net:
                raise ERROR_exception("no route provided")
            else:
                route = self.net["route"]

            if "gateway" not in self.net:
                raise ERROR_exception("no gateway provided")
            else:
                gateway = self.net["gateway"]


            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            subprocess.call(["ssh-keygen", "-R", self.host], stdout=devnull, stderr=devnull)
            client.connect(self.host, username=self.user, password=self.password, 
                           timeout=max_span, banner_timeout=max_span)
            message.append("connection established")

            # Add temporary route
            (stdin, stdout, stderr) = client.exec_command("route add " + route + " " + gateway)
            error = stderr.read().strip("\n")
            out_put = stdout.read().strip("\n")

            if error:
                raise ERROR_exception(error + " " + out_put)
            else:
                message.append(out_put)

            # If user decide to a add route permanently, write to rc.conf
            if self.perm:
                sftp = client.open_sftp()
                
                with sftp.open("/etc/rc.conf","r") as f:
                    lines = f.readlines()

                found_route = False
                for idx, line in enumerate(lines):
                    line = str(line)
                    if "static_routes" in line:
                        found_route = True
                        route_list = line.split('=')[1].replace("\"","").strip("\n").split(" ")
                        # Find an indexed name
                        n=0
                        while ("net" + str(n)) in route_list:
                            n = n + 1
                        route_name = "net" + str(n)
                        route_list.append(route_name)
                        lines[idx] = "static_routes=\"" + " ".join(route_list) + "\"" + "\n"
                
                if not found_route:
                    route_name = "net0"
                    lines.append("static_routes=\"net0\"\n")

                lines.append("route_" + route_name + "=\"-net " + route + " " + gateway + "\"" + "\n")

                # wite the modified lines to rc.conf
                with sftp.open("/etc/rc.conf", "w") as f:
                    f.write("".join(lines))

                message.append("writing to rc.conf")

            client.close()
                
        
        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, 
                paramiko.SSHException, ERROR_exception) as e:
            
            return_dict["success"] = "False"
            meta_dict = meta.meta_header()
            if hasattr(e, "msg"):
                return_dict["error"] = e.msg
            else:
                return_dict["error"] = str(e)
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:
            return_dict["success"] = "True"
            meta_dict = meta.meta_header()
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)

