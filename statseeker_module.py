#!/usr//bin/python

import base
import json
import meta
import os
from subprocess import call
from subprocess import check_output
import paramiko
import socket
import errno
import re
import sys
import random
import re


#
# Custom exception
#

class ERROR_exception(Exception):
        def __init__(self, msg):
            self.msg = msg


#
# auto_iso_gen: this module take a statseeker iso and modify it to enable unattended install require explicit moded installerconfig
#

class auto_iso_gen(base.statseeker_base):
    description = "this module modify the selected statseeker iso to allow config install"

    def __init__(self, interface, ip, netmask, router, hostname, dns, password, mod_config, iso_orig, iso_mod):
        super(auto_iso_gen, self).__init__("auto_iso_gen", "5.x")
        self.interface = interface
        self.ip = ip
        self.netmask = netmask
        self.router = router
        self.hostname = hostname
        self.dns = dns
        self.password = password
        self.mod_config = mod_config
        self.iso_orig = iso_orig
        self.iso_mod = iso_mod
        self.domain = hostname.split("@")[1]

    def main(self):
        
        return_dict = {}
        message = []
        devnull = open(os.devnull, 'w')

        try:
            # test if this module is run as the root user
            if os.geteuid() != 0:
                raise ERROR_exception("root priviledge is needed to run this script")

            # test if the provided mod_config and iso images are valid files
            if not os.path.isfile(self.mod_config):
                raise ERROR_exception("the provided installerconfig does not exist!")
            
            if not os.path.isfile(self.iso_orig):
                raise ERROR_exception("the provided statseeker iso does not exist!")

            # mounting and copying process differs according to os
            system = check_output(["uname"]).rstrip()

            if system == "Linux":
                message.append("mounting the iso image....")
                call([ "mkdir", "/dev/mnt" ], stdout=devnull, stderr=devnull)
                call([ "mount", self.iso_orig, "/dev/mnt" ], stdout=devnull, stderr=devnull)

                message.append("copy the mounted directory....")
                call([ "cp", "-r", "/dev/mnt", "disk"])

            elif system == "FreeBSD":
                message.append("mounting the iso image....")
                md = "/dev/" + check_output([ "mdconfig", "-a", "-t", "vnode", "-f", self.iso_orig]).rstrip()
                call([ "mount", "-t", "cd9660", md, "/mnt" ], stdout=devnull, stderr=devnull)

                message.append("copy the mounted directory....")
                call([ "cp", "-r", "/mnt/", "disk/"], stdout=devnull, stderr=devnull)

            else:
                raise ERROR_exception("This module must be run on Linux or Freebsd platform")


            message.append("creating the auto_install config file")

            with open("disk/etc/auto_install_config", 'w') as config:
                config.write("auto_interface=" + self.interface + "\n")
                config.write("auto_ip_address=" + self.ip + "\n")
                config.write("auto_netmask=" + self.netmask + "\n")
                config.write("auto_default_router=" + self.router + "\n")
                config.write("auto_hostname=" + self.hostname + "\n")
                config.write("auto_ipv4_dns=" + self.dns + "\n")
                config.write("auto_password=" + self.password + "\n")
                config.write("auto_domain=" + self.domain + "\n")
                config.write("auto_dns=" + self.dns + "\n")
            
            message.append("copying modified installerconfig file....")
            call([ "cp", self.mod_config, "disk/etc/installerconfig"], stdout=devnull, stderr=devnull)


            if system == "Linux":
                message.append("umount the iso image")
                call([ "umount", "/dev/mnt/"], stdout=devnull, stderr=devnull)
            else:
                message.append("umount /mnt and delete the memory disk")
                call([ "umount", "-f", "/mnt"], stdout=devnull, stderr=devnull)
                call([ "mdconfig", "-du", md ])

            message.append("creating iso image...")

            if not call(["mkisofs", "-rT", "-ldots", "-b", "boot/cdboot", "-no-emul-boot", "-V", "STATSEEKER_INSTALL", "-o", self.iso_mod, "disk"], stdout=devnull, stderr=devnull):
                message.append(self.iso_mod + " has been created successfully")

                message.append("iso created, remove copied directories")
                call(["rm", "-rf", "disk"])

            else: 
                message.append("failed to create iso, remove copied directories")
                call(["rm", "-rf", "disk"])

                raise ERROR_exception("something when wrong during repackaging of the iso")

            
        except ERROR_exception as e:

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
# license: this module licenses a statseeker box 
#

class licence(base.statseeker_base):
    description = "This module licence a statseeker box"

    def __init__(self, ip, server_id, user, password):
        super(licence, self).__init__("licence", "5.x")
        self.ip = ip
        self.server_id = server_id
        self.user = user
        self.password = password

    def main(self):
        return_dict = {}
        message = []

        ss_url = "http://" + self.ip + "/cgi/ssAdminTool-licence"
        request_method = "GET"
        cgi_bin = "/cgi/wwwc08"
        key_server = "http://key-server.statseeker.com"

        client = paramiko.SSHClient()

        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.ip, username=self.user, password=self.password)
            (stdin, stdout, stderr) = client.exec_command("/usr/local/statseeker/ss/bin/lic-check -H")
            hardware_id = stdout.read()
            query_string = "server_id=" + self.server_id + "&hardware_id=" + hardware_id + "&referurl=" + ss_url

            message.append("Aquiring license from license server")
            LICENCE_TEXT = check_output(["wget", "-q", key_server + cgi_bin + "?" + query_string, "-O", "-"])

            for line in LICENCE_TEXT.split("\n"):
                if "product_key" in line:
                    LICENCE = re.sub('[">]', '', line.split("value=\"")[-1])

            if not (LICENCE and LICENCE.isdigit()):
                raise ERROR_exception("failed to aquire the license key")
            
            message.append("Adding server_id to base.cfg")
            client.exec_command("/usr/local/statseeker/ss/bin/base-cfg -s /home/statseeker/base/etc/base.cfg server_number " + self.server_id)
            message.append("Adding licence")
            client.exec_command("/usr/local/statseeker/ss/bin/lic-check -i" + "\"" + LICENCE +"\"")

            message.append("licence checking")
            (stdin, stdout, stderr) = client.exec_command("/usr/local/statseeker/ss/bin/lic-check")
            
            if stdout.channel.recv_exit_status():
                raise ERROR_exception("invalid license")
            else:
                message.append("license is valid")

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
# add_scan_range: this module add ip scan ranges to a statseeker box
#
class add_scan_range(base.statseeker_base):
    description = "This module add ip scan ranges to a statseeker box"

    def __init__(self, host, user, password, *ranges):
        super(add_scan_range, self).__init__("add_scan_range", "5.x")
        self.host = host
        self.user = user
        self.password = password
        self.ranges = ranges

    def main(self):
        return_dict = {}
        message = []

        client = paramiko.SSHClient()
        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            sftp = client.open_sftp()

            with sftp.open("/home/statseeker/nim/etc/ping-discover-ranges.cfg", "a") as f:

                for ip_range in self.ranges:
                    f.write("include " + ip_range + "\n")
                    message.append("include " + ip_range) 

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
# add_community: this module add new communities to a statseeker box
#
class add_community(base.statseeker_base):
    description = "This module add new communities to a statseeker box"

    def __init__(self, host, user, password, *communities):
        super(add_community, self).__init__("add_community", "5.x")
        self.host = host
        self.user = user
        self.password = password
        self.communities = communities

    def main(self):
        return_dict = {}
        message = []

        client = paramiko.SSHClient()
        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            sftp = client.open_sftp()

            with sftp.open("/home/statseeker/nim/etc/community.cfg", "a") as f:

                for community in self.communities:
                    f.write(community + "\n")
                    message.append("added " + community) 

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
# run_api_command module: run api command, this is quite similar to remote_mdoule.run_command, except that the 
# success field is not only determined by the exit signal but the success field of the returned result, the input
# format is also changed to one or a list of python dictionaries 
#
class run_api_command(base.statseeker_base):
    description = 'run a api commands on the a remote statseeker box'

    def __init__(self, host, user, password, commands):
        super(run_api_command, self).__init__("run_api_command", "> 4.x")
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
            if isinstance(self.commands, (list,tuple)):

                for item in self.commands:
                    command = "nim-api " + "\'" + json.dumps(item) + "\'"
                    message.append("running: " + command)
                    command_app = pre_command + command
                    (stdin, stdout, stderr) = client.exec_command(command_app, get_pty=True)
                    error = stderr.read()
                    out_put = stdout.read()
                    success = json.loads(out_put)["success"]

                    if error or stdout.channel.recv_exit_status() or not success:
                        raise ERROR_exception(error + out_put)
                    else:
                        result.append(out_put)

            elif isinstance(self.commands, dict):
                command = "nim-api " + "\'" + json.dumps(self.commands) + "\'"
                message.append("running " + command)
                command_app = pre_command + command
                (stdin, stdout, stderr) = client.exec_command(command_app, get_pty=True)
                error = stderr.read()
                out_put = stdout.read()
                success = json.loads(out_put)["success"]

                if error or stdout.channel.recv_exit_status() or not success:
                    raise ERROR_exception(error + out_put)
                else:
                    result.append(out_put)

            else:
                raise ERROR_exception("Input commands are given in invalid format")

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
            return_dict["result"] = result
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:

            return_dict["success"] = "True"
            meta_dict = meta.meta_header()
            return_dict["result"] = result
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)

