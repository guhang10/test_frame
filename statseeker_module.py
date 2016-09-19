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
from HTMLParser import HTMLParser
import re

#
# Custom exception
#

class ERROR_exception(Exception):
        def __init__(self, msg):
            self.msg = msg


#
# auto_iso_gen: this module take a statseeker 5.x iso and modify it to enable unattended install 
#

class auto_iso_gen(base.statseeker_base):
    description = "this module modify the selected statseeker iso to allow config install"

    def __init__(self, interface, ip, netmask, router, hostname, dns, password, iso_orig, iso_mod):
        super(auto_iso_gen, self).__init__("auto_iso_gen", "5.x")
        self.interface = interface
        self.ip = ip
        self.netmask = netmask
        self.router = router
        self.hostname = hostname
        self.dns = dns
        self.password = password
        self.iso_orig = iso_orig
        self.iso_mod = iso_mod
        self.domain = hostname.split("@")[1]

    def main(self):
        
        return_dict = {}
        message = []
        devnull = open(os.devnull, 'w')

        try:
            message.append("mounting the iso image....")
            call([ "mkdir", "/dev/mnt" ], stdout=devnull, stderr=devnull)
            call([ "mount", self.iso_orig, "/dev/mnt" ], stdout=devnull, stderr=devnull)

            message.append("copy the mounted directory....")
            call([ "cp", "-r", "/dev/mnt", "disk"])

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

            message.append("umount the iso image")
            call([ "umount", "/dev/mnt/"], stdout=devnull, stderr=devnull)

            message.append("copying modified installerconfig file....")
            call([ "cp", "install_conf/installerconfig_mod", "disk/etc/installerconfig"], stdout=devnull, stderr=devnull)

            message.append("creating test.iso....")

            if not call(["mkisofs", "-rT", "-ldots", "-b", "boot/cdboot", "-no-emul-boot", "-V", "STATSEEKER_INSTALL", "-o", self.iso_mod, "disk"], stdout=devnull, stderr=devnull):
                message.append("done, remove copied directories")
                call(["rm", "-rf", "disk"])

            else:
                raise ERROR_exception("something when wrong during repackaging of the iso")
            
        except ERROR_exception as e:

            return_dict["success"] = "false"
            meta_dict = meta.meta_header()
            return_dict["error"] = e.msg
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        return_dict["success"] = "true"
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

        self.client = paramiko.SSHClient()

        try:
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.ip, username=self.user, password=self.password)
            self.client.exec_command(". ~/.profile")
            (stdin, stdout, stderr) = self.client.exec_command("/usr/local/statseeker/ss/bin/lic-check -H")
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
            self.client.exec_command("/usr/local/statseeker/ss/bin/base-cfg -s /home/statseeker/base/etc/base.cfg server_number " + self.server_id)
            message.append("Adding licence")
            self.client.exec_command("/usr/local/statseeker/ss/bin/lic-check -i" + "\"" + LICENCE +"\"")

            self.client.close()

        except(paramiko.BadHostKeyException, paramiko.AuthenticationException, 
                paramiko.SSHException, socket.error, ERROR_exception) as e:

            return_dict["success"] = "false"
            meta_dict = meta.meta_header()
            return_dict["error"] = e.msg
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        return_dict["success"] = "true"
        meta_dict = meta.meta_header()
        return_dict["message"] = message
        return_dict["meta"] = meta_dict.main()
        return json.dumps(return_dict)

