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

#
# ssh_check module: check the ssh connectivity to host. require "pip install paramiko"
#

class ssh_check(base.local_base):
    description = "checking ssh connectivity to host"

    def __init__(self, cred, password, key_file):
        super(ssh_check, self).__init__("ss_check", "n/a")
        self.key = key_file
        [self.user, self.ip] = cred.split("@")
        self.password = password
        
    def main(self):
        self.client = paramiko.SSHClient()
        try:
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, username=self.user, password=self.password, key_filename=self.key)
            print "connect to " + self.ip + " successfully"
            client.close()
            return True
            
        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, 
                paramiko.SSHException, socket.error) as e:
            print "ssh connection failed"
            print e
            return False

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

#task_run_script = run_script("statseeker@10.2.26.141", "qa", "/home/hang/.ssh/id_rsa", "test.sh", "/home/statseeker/test.sh")
#task_run_script.main()


#
# vcenter_details module: display vcenter details
#
class vcenter_details(vmware_base):
    description = "Getting vcenter details"
    from pyVim import connect
    from pyVmomi import vmodl
    from pyVmomi import vim

    def __init__(self, host, user, pwd):
        self.host = host
        self.user = user
        self.pwd = pwd









