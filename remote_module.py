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
import socket
import traceback

#
# Custom exception
#

class ERROR_exception(Exception):
        def __init__(self, msg):
            self.msg = msg

#
# output_builder
#
def output_builder(message, error, fail, **kwargs):
    return_dict = {}
    meta_dict = meta.meta_header()
    return_dict["meta"] = meta_dict.main()
    return_dict["message"] = message
    
    if fail:
        return_dict["error"] = error
        return_dict["success"] = False
    else:
        return_dict["success"] = True

    if "result" in kwargs:
        return_dict["result"] = kwargs["result"]

    return json.dumps(return_dict)


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
        max_span = 20

        try:
            while True:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    subprocess.call(["ssh-keygen", "-R", self.host], stdout=devnull, stderr=devnull)
                    client.connect(self.host, username=self.user, password=self.password, 
                                   timeout=max_span, banner_timeout=max_span)
                    # close the parmiko client
                    clien.close

                except socket.error:
                    pass
                else:
                    message.append("connection established")
                    break

        # exception capture
        except ERROR_exception as e:
            return output_builder(message, e.msg, 1)
        except paramiko.BadHostKeyException:
            return output_builder(message, "bad host key", 1)
        except paramiko.AuthenticationException:
            return output_builder(message, "authentication exception", 1)
        except paramiko.SSHException:
            return output_builder(message, "ssh exception", 1)
        except Exception:
            return output_builder(message, 'generic exception: ' + traceback.format_exc(), 1)
        else:
            return output_builder(message,'', 0)


#
# upload_script module: upload, (run and remove) a script from local to remote host
#
class upload_script(base.remote_base):
    description = 'upload, run and remove a script from local to remote host'

    def __init__(self, host, user, password, run, delete, local, remote, **kwargs):
        super(upload_script, self).__init__("upload_script", "n/a")
        self.remote = remote
        self.local = local
        self.run = run
        self.delete = delete
        self.host = host
        self.user = user
        self.password = password
        self.kwargs = kwargs

    def main(self):
        message = []
        result = []

        try:
            client = paramiko.SSHClient()
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
                command = "./" + self.remote

                if "option" in self.kwargs:
                    command = command + " " + self.kwargs["option"]

                (stdin, stdout, stderr) = client.exec_command(command)
                error = stderr.read()
                out_put = stdout.read()

                if error or stdout.channel.recv_exit_status():
                    raise ERROR_exception(error)
                else:
                    result.append(out_put)

            #removing the file on the remote host
            if self.delete:
                client.exec_command("rm -rf " + self.remote) 
                message.append("removed" + self.remote)
            
            #close the pipe
            client.close()

        # exception capture
        except ERROR_exception as e:
            return output_builder(message, e.msg, 1)
        except paramiko.BadHostKeyException:
            return output_builder(message, "bad host key", 1)
        except paramiko.AuthenticationException:
            return output_builder(message, "authentication exception", 1)
        except paramiko.SSHException:
            return output_builder(message, "ssh exception", 1)
        except socket.error:
            return output_builder(message, "socket error", 1)
        except Exception:
            return output_builder(message, 'generic exception: ' + traceback.format_exc(), 1)
        else:
            return output_builder(message,'', 0, result=result)


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

        try:
            # Validate input output paring
            if len(self.local_remote["local"]) != len(self.local_remote["remote"]):
                raise ERROR_exception("number of local files given doesn't match the remote locations")

            # Validate the local file
            for file in self.local_remote["local"]:
                if not os.path.isfile(file):
                    raise ERROR_exception("The local file " + file +  " is not valid")

            # Connect to remote host
            client = paramiko.SSHClient()
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

       # exception capture
        except ERROR_exception as e:
            return output_builder(message, e.msg, 1)
        except paramiko.BadHostKeyException:
            return output_builder(message, "bad host key", 1)
        #except paramiko.AuthenticationException:
            return output_builder(message, "authentication exception", 1)
        except paramiko.SSHException:
            return output_builder(message, "ssh exception", 1)
        except socket.error:
            return output_builder(message, "socket error", 1)
        except Exception:
            return output_builder(message, 'generic exception: ' + traceback.format_exc(), 1)
        else:
            return output_builder(message,'', 0)


#
# run_command module: run commands on a remote host
#
class run_command(base.remote_base):
    description = 'run a commands on the remote host'

    def __init__(self, host, user, password, commands):
        super(run_command, self).__init__("run_command", "n/a")
        self.user = user
        self.host = host
        self.password = password
        self.commands = commands

    def main(self):
        message = []
        result = []

        try:
            client = paramiko.SSHClient()
            # Connect to remote host
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            # load the ~/.profile before running commands nop, not for statseeker
            pre_command = ". ~/.profile;"
            
            # execute the given list of commands
            if isinstance(self.commands, (list,tuple)):

                for command in self.commands:
                    message.append("running: " + command)
                    command_app = pre_command + command
                    (stdin, stdout, stderr) = client.exec_command(command_app, get_pty=True)
                    error = stderr.read()
                    out_put = stdout.read()

                    if error or stdout.channel.recv_exit_status():
                        raise ERROR_exception(error + out_put)
                    else:
                        result.append(out_put)

            elif isinstance(self.commands, basestring):
                message.append("running " + self.commands)
                command_app = pre_command + self.commands
                (stdin, stdout, stderr) = client.exec_command(command_app, get_pty=True)
                error = stderr.read()
                out_put = stdout.read()

                if error or stdout.channel.recv_exit_status():
                    raise ERROR_exception(error + out_put)
                else:
                    result.append(out_put)

            else:
                raise ERROR_exception("Input commands are given in invalid format")

            #close the pipe
            client.close()

        # exception capture
        except ERROR_exception as e:
            return output_builder(message, e.msg, 1)
        except paramiko.BadHostKeyException:
            return output_builder(message, "bad host key", 1)
        except paramiko.AuthenticationException:
            return output_builder(message, "authentication exception", 1)
        except paramiko.SSHException:
            return output_builder(message, "ssh exception", 1)
        except socket.error:
            return output_builder(message, "socket error", 1)
        except Exception:
            return output_builder(message, 'generic exception: ' + traceback.format_exc(), 1)
        else:
            return output_builder(message,'', 0, result=result)


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
        max_span = 20

        try:
            client = paramiko.SSHClient()
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

            # close the paramiko client
            client.close()
                    
        # exception capture
        except ERROR_exception as e:
            return output_builder(message, e.msg, 1)
        except paramiko.BadHostKeyException:
            return output_builder(message, "bad host key", 1)
        except paramiko.AuthenticationException:
            return output_builder(message, "authentication exception", 1)
        except paramiko.SSHException:
            return output_builder(message, "ssh exception", 1)
        except socket.error:
            return output_builder(message, "socket error", 1)
        except Exception:
            return output_builder(message, 'generic exception: ' + traceback.format_exc(), 1)
        else:
            return output_builder(message,'', 0)


