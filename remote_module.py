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
# run_script module: upload, run and remove a script from local to remote host
#
class run_script(base.remote_base):
    description = 'upload, run and remove a script from local to remote host'

    # Supported file types dictionary, expand when necessary
    types = {"py": "pyhon", "sh": "sh"}

    def __init__(self, cred, password, key_file, local, remote):
        super(run_script, self).__init__("run_script", "n/a")
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



