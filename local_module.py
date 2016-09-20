#
# This file contains modules that will be use as bases of tasks, modules perform the key functions of the test
# every module will contain a main function that execute the logic 
# task.
# Modules will be result oriented, it will return both the result(fail or pass) and a meta field (a report that contains the returned value or text
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
# ssh_check module: check the ssh connectivity to host. require "pip install paramiko"
#

class ssh_check(base.local_base):
    description = "checking ssh connectivity to host"

    def __init__(self, cred, password):
        super(ssh_check, self).__init__("ss_check", "n/a")
        [self.user, self.ip] = cred.split("@")
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
                    client.connect(self.ip, username=self.user, password=self.password, 
                                   timeout=max_span, banner_timeout=max_span)
                    client.close()
                    
                except socket.error:
                    pass
                
                else:
                    message.append("connection established")
                    break
        
        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, 
                paramiko.SSHException) as e:
            
            return_dict["success"] = "false"
            meta_dict = meta.meta_header()
            return_dict["error"] = str(e)
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:
            return_dict["success"] = "true"
            meta_dict = meta.meta_header()
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)


#
# run_script module: upload, run and remove a script from local to remote host
#
class run_script(base.script_base):
    description = 'upload, run and remove a script from local to remote host'

    # Supported file types dictionary, expand when necessary
    types = {"py": "pyhon", "sh": "sh"}

    def __init__(self, cred, password, key_file, local, remote):
        super(run_script, self).__init__("run_script", "n/a", local)
        self.remote = remote
        self.key = key_file
        [self.user, self.ip] = cred.split("@")
        self.password = password
        self.interpreter = run_script.types[self.script_type]

    def main(self):
        self.client = paramiko.SSHClient()
        try:
            # Connect to remote host
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, username=self.user, password=self.password, key_filename=self.key)

            # Setup sftp connection and transmit this script
            sftp = self.client.open_sftp()
            sftp.put(self.local, self.remote) 
            sftp.close()

            # Run the script remotely and collect output
            # SSHClient.exec_command() returns the type (stdin, stdout, stderr)
            (stdin, stdout, stderr) = self.client.exec_command(self.interpreter + " " + self.remote)
            
            #removing the file on the remote host
            self.client.exec_command("rm -rf " + self.remote) 
            
            # Output analysis
            print stdout.read()

            #close the pipe
            self.client.close()
            return True

        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, paramiko.SSHException, 
                socket.error, OSError) as e:
            print "ssh connection failed"
            print e
            return False


#
# ping_test module: ping an ip until it's up or the time runs out
#
class ping_test(base.local_base):
    description = 'ping a box until a box come up or the maximum time limit is reached'

    def __init__(self, ip, max_span):
        super(ping_test, self).__init__("ping test", "n/a")
        self.ip = ip
        self.max_span = str(max_span)

    def main(self):
        message = []
        return_dict = {}
        devnull = open(os.devnull, 'w')

        try:
            result = subprocess.call(["ping", "-c", "2", "-w", self.max_span, self.ip], stdout=devnull, stderr=devnull)
            
            if not result:
                message.append("ping response received")
            else:
                raise ERROR_exception("ping response is not received within the time limit")

        except ERROR_exception as e:

            return_dict["success"] = "false"
            meta_dict = meta.meta_header()
            return_dict["error"] = e.msg
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:
            return_dict["success"] = "true"
            meta_dict = meta.meta_header()
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)






