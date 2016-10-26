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
import string
import re
import traceback
from pprint import pprint
import urllib2


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
# auto_iso_gen: this module take a statseeker iso and modify it to enable unattended install require explicit moded installerconfig
#

class auto_iso_gen(base.statseeker_base):
    description = "this module modify the selected statseeker iso to allow config install"

    def name_gen(self, size=6, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def __init__(self, interface, ip, netmask, router, hostname, dns, password, timezone, mod_config, iso_orig, iso_mod):
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
        hostname = hostname.split(".")
        self.domain = ".".join([hostname[1], hostname[2]])
        self.timezone = timezone 

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

            # randomize the name of the temporary directory so multiple isos can be generated simultaneously
            copy_dir = self.name_gen(4, "6793YUIOFTESP")

            if system == "Linux":
                message.append("mounting the iso image....")
                call([ "mkdir", "/dev/mnt" ], stdout=devnull, stderr=devnull)
                call([ "mount", self.iso_orig, "/dev/mnt" ], stdout=devnull, stderr=devnull)
                message.append("success")

                message.append("copy the mounted directory content to " + copy_dir)
                call([ "cp", "-r", "/dev/mnt", copy_dir])
                message.append("success")

            elif system == "FreeBSD":
                message.append("mounting the iso image....")
                md = "/dev/" + check_output([ "mdconfig", "-a", "-t", "vnode", "-f", self.iso_orig]).rstrip()
                call([ "mount", "-t", "cd9660", md, "/mnt" ], stdout=devnull, stderr=devnull)
                message.append("success")

                message.append("copy the mounted directory content to " + copy_dir)
                call([ "cp", "-r", "/mnt/", copy_dir], stdout=devnull, stderr=devnull)
                message.append("success")

            else:
                raise ERROR_exception("This module must be run on Linux or Freebsd platform")


            message.append("creating the auto_install config file")

            with open(copy_dir + "/etc/auto_install_config", 'w') as config:
                config.write("auto_interface=" + self.interface + "\n")
                config.write("auto_ip_address=" + self.ip + "\n")
                config.write("auto_netmask=" + self.netmask + "\n")
                config.write("auto_default_router=" + self.router + "\n")
                config.write("auto_hostname=" + self.hostname + "\n")
                config.write("auto_ipv4_dns=" + self.dns + "\n")
                config.write("auto_password=" + self.password + "\n")
                config.write("auto_domain=" + self.domain + "\n")
                config.write("auto_dns=" + self.dns + "\n")
                config.write("auto_timezone=" + self.timezone + "\n")
            
            message.append("copying modified installerconfig file....")
            call([ "cp", self.mod_config, copy_dir + "/etc/installerconfig"], stdout=devnull, stderr=devnull)
            message.append("success")


            if system == "Linux":
                message.append("umounting the iso image")
                call([ "umount", "/dev/mnt/"], stdout=devnull, stderr=devnull)
                message.append("success")
            else:
                message.append("umount /mnt and delete the memory disk")
                call([ "umount", "-f", "/mnt"], stdout=devnull, stderr=devnull)
                call([ "mdconfig", "-du", md ])
                message.append("success")

            message.append("creating iso image: " + self.iso_mod)

            if not call(["mkisofs", "-rT", "-ldots", "-b", "boot/cdboot", "-no-emul-boot", "-V", "STATSEEKER_INSTALL", "-o", self.iso_mod, copy_dir], stdout=devnull, stderr=devnull):
                message.append("success")

                message.append("remove the copied directory")
                call(["rm", "-rf", copy_dir])
                message.append("success")

            else: 
                message.append("failed to create iso, remove copied directories")
                call(["rm", "-rf", copy_dir])
                message.append("success")

                raise ERROR_exception("something when wrong during repackaging of the iso")

        # exception capture
        except ERROR_exception as e:
            return output_builder(message, e.msg, 1)
        except Exception:
            return output_builder(message, 'generic exception: ' + traceback.format_exc(), 1)
        else:
            return output_builder(message,'',0)



#
# license: this module licenses a statseeker box 
#

class licence(base.statseeker_base):
    description = "This module licence a statseeker box"

    def __init__(self, ip, ss_ver, server_id, user, password):
        super(licence, self).__init__("licence", "5.x/4.x")
        self.ip = ip
        self.server_id = server_id
        self.user = user
        self.password = password
        self.ss_ver = ss_ver[0]

    def main(self):
        return_dict = {}
        message = []

        ss_url = "http://" + self.ip + "/cgi/ssAdminTool-licence"
        request_method = "GET"

        # cgi_bin version
        if self.ss_ver == "5":
            cgi_bin = "/cgi/wwwc08"
        elif self.ss_ver == "4":
            cgi_bin = "/cgi/wwwc07"
        else:
            raise ERROR_exception("This statseeker version is not supported")

        key_server = "http://key-server.statseeker.com"

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.ip, username=self.user, password=self.password)
            (stdin, stdout, stderr) = client.exec_command("/usr/local/statseeker/ss/bin/lic-check -H")
            hardware_id = stdout.read().strip('\n')
            query_string = "server_id=" + self.server_id + "&hardware_id=" + hardware_id + "&referurl=" + ss_url

            message.append("Aquiring license from license server")
            LICENCE_TEXT = check_output(["wget", "-q", key_server + cgi_bin + "?" + query_string, "-O", "-"])

            for line in LICENCE_TEXT.split("\n"):
                if "product_key" in line:
                    LICENCE = re.sub('[">]', '', line.split("value=\"")[-1])
                    message.append("success")

            if not (LICENCE and LICENCE.isdigit()):
                raise ERROR_exception("failed to aquire the license key")
            
            message.append("Adding server_id to base.cfg")
            client.exec_command("/usr/local/statseeker/ss/bin/base-cfg -s /home/statseeker/base/etc/base.cfg server_number " + self.server_id)
            message.append("success")

            message.append("Adding licence")
            client.exec_command("/usr/local/statseeker/ss/bin/lic-check -i" + "\"" + LICENCE +"\"")
            message.append("success")

            message.append("licence checking")
            (stdin, stdout, stderr) = client.exec_command("/usr/local/statseeker/ss/bin/lic-check")
            
            if stdout.channel.recv_exit_status():
                raise ERROR_exception("invalid license")
            else:
                message.append("success")
        
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

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            sftp = client.open_sftp()

            message.append("adding scan range: " + ", ".join(self.ranges))

            with sftp.open("/home/statseeker/nim/etc/ping-discover-ranges.cfg", "a") as f:

                for ip_range in self.ranges:
                    f.write("include " + ip_range + "\n")
                    message.append("include " + ip_range) 

            message.append("success")
        
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

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            sftp = client.open_sftp()

            with sftp.open("/home/statseeker/nim/etc/community.cfg", "a") as f:

                message.append("Adding community: " + ",".join(self.communities))
                for community in self.communities:
                    f.write(community + "\n")
                    message.append("added " + community) 
                message.append("success")
        
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

    def shell_escape(self, arg):
        return "%s" % (arg.replace(r"'", r"\'"), )

    def rm_emp_line(self, string):
        return filter(lambda x: not re.match(r'^\s*$', x), string)

    def main(self):
        return_dict = {}
        message = []
        result = []

        try:
            client = paramiko.SSHClient()
            # Connect to remote host
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            # execute the given list of commands
            if isinstance(self.commands, (list,tuple)):

                for item in self.commands:
                    command = json.dumps(item) 
                    message.append("running " + command)
                    (stdin, stdout, stderr) = client.exec_command("/usr/local/statseeker/ss/bin/nim-api")
                    stdin.write(command + "\nquit\n")
                    stdin.flush()
                    error = stderr.read()
                    out_put = stdout.read()
                    success = json.loads(out_put)["success"]

                    if error or stdout.channel.recv_exit_status() or not success:
                        raise ERROR_exception(error + out_put)
                    else:
                        result.append(json.loads(self.rm_emp_line(out_put)))
                        message.append("success")

            elif isinstance(self.commands, dict):
                command = json.dumps(self.commands) 
                message.append("running " + command)
                (stdin, stdout, stderr) = client.exec_command("/usr/local/statseeker/ss/bin/nim-api")
                stdin.write(command + "\nquit\n")
                stdin.flush()
                error = stderr.read()
                out_put = stdout.read()
                success = json.loads(out_put)["success"]

                if error or stdout.channel.recv_exit_status() or not success:
                    raise ERROR_exception(error + out_put)
                else:
                    result.append(json.loads(self.rm_emp_line(out_put)))
                    message.append("success")

            # close the client
            client.close()

            else:
                raise ERROR_exception("Input commands are given in invalid format")

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
# get_base_logd: this module get base_logd log from a statseeker box and applies filters 
#
class get_base_logd(base.statseeker_base):
    description = "This module retrieves base_logd and applies apecific filter"

    def __init__(self, host, user, password, *filters):
        super(get_base_logd, self).__init__("get_base_logd", "N/A")
        self.host = host
        self.user = user
        self.password = password
        self.filters = filters

    def main(self):
        return_dict = {}
        message = []

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            sftp = client.open_sftp()

            with sftp.open("/home/statseeker/base/logs/base-logd.log", "r") as f:
                base_log = f.readlines()
        
            # close the paramiko client
            client.close()

        # Exception handeling
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




#
# ss_restore: verifies and runs a restore of a chosen backup, reboot statseeker and then do a rewalk
#
class ss_restore(base.statseeker_base):
    description = "This module verifies and runs a restore of a chosen backup"
    
    def __init__(self, host, root_pass, backup_host, backup_user, backup_pass, backup_dir, backup_name):
        super(ss_restore, self).__init__("ss_restore", "N/A")
        self.host = host
        self.user = "root"
        self.password = root_pass
        self.backup_host = backup_host
        self.backup_user = backup_user
        self.backup_pass = backup_pass
        self.backup_dir = backup_dir
        self.backup_name = backup_name

    def main(self):
        return_dict = {}
        message = []

        # load the ~/.profile before running commands nop, not for statseeker
        pre_command = ". ~/.profile;"
            
        # preconfigure backup.cfg text
        backup_cfg = ["# shell 3 15 1",
                      "Days=\'\'", 
                      "FTPCycle=\'2\'",
                      "FTPPassiveMode=\'NO\'", 
                      "FTPPassword=\'" + self.backup_pass + "\'",
                      "FTPPort=\'21\'",
                      "FTPRemoteDirectory=\'" + self.backup_dir + "\'",
                      "FTPRemoteMachineIP=\'" + self.backup_host + "\'",
                      "FTPUserName=\'" + self.backup_user + "\'",
                      "LOCALCycle=\'2\'",
                      "Method=\'ftp\'",
                      "SSHCycle=\'2\'",
                      "StartHour=\'4\'",
                      "StartMinute=\'0\'",
                      "TestSize=\'10485760\'"]

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user, password=self.password)

            # populate /home/statseeker/base/etc/base.cfg
            sftp = client.open_sftp()
            backup_file = "/home/statseeker/base/etc/backup.cfg"

            with sftp.open(backup_file, "w") as f:
                message.append("populating backup.cfg")
                f.write('\n'.join(backup_cfg) + '\n')
                message.append("success")

            # change the owner of the config to statseeker
            message.append("Change backup.cfg's owner to statseeker")
            (stdin, stdout, stderr) = client.exec_command(pre_command + "chown " + "statseeker " + backup_file)
            error = stderr.read()
            output = stdout.read()

            if error or stdout.channel.recv_exit_status():
                raise ERROR_exception(error + output)
            else:
                message.append("success")


            # testing the configuration
            message.append("verifying backup")
            (stdin, stdout, stderr) = client.exec_command(pre_command + "base-backup -k", get_pty=True)
            error = stderr.read()
            output = stdout.read()

            if error or stdout.channel.recv_exit_status():
                raise ERROR_exception(error + output)
            else:
                message.append("success")

            # starting the restore
            message.append("starting restore")
            (stdin, stdout, stderr) = client.exec_command(pre_command + "base-backup -r " + self.backup_name, get_pty=True)
            error = stderr.read()
            output = stdout.read()
            
            if error or stdout.channel.recv_exit_status():
                raise ERROR_exception(error + output)
            else:
                message.append("success")

            # restarting statseeker
            message.append("restarting statseeker")
            (stdin, stdout, stderr) = client.exec_command(pre_command + "service statseeker.sh restart", get_pty=True)
            error = stderr.read()
            output = stdout.read()

            if error or stdout.channel.recv_exit_status():
                raise ERROR_exception(error + output)
            else:
                message.append("success")
            
            # close the paramiko client
            client.close()

        # Exception handeling
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
            return output_builder(message, '', 0)



#
# ss_auto_grouping: addeing a autogrouping rule to statseeker
# TODO: adding write api method when it's ready
#

class ss_auto_grouping(base.statseeker_base):
    description = "This module insert existing autogrouping configs or create new autogrouping rules"
    
    def __init__(self, host, ss_user, ss_password, method, json_str):
        super(ss_auto_grouping, self).__init__("ss_auto_grouping", "4.x/5.x")
        self.ss_host = host
        self.ss_user = ss_user
        self.ss_password = ss_password
        self.method = method
        self.json_str = json_str
        self.group_info = json.loads(json_str)

    def main(self):
        message = []

        # load the ~/.profile before running commands nop, not for statseeker
        pre_command = ". ~/.profile;"
         

        if self.method == "ssperl":
            # constructing the script to go with ssperl
            auto_group_command = "\'" + "".join(["use nim;", 
                                                 "use AutogroupCommon;",
                                                 "use JSON::XS;", 
                                                 "my $name = \"" + self.group_info["name"] + "\";",
                                                 "my $data = qq|" + self.json_str + "|;",
                                                 "my $cfg = decode_json($data);",
                                                 "AutogroupCommon->save_group($name, $cfg);"]) + "\'"

        client = paramiko.SSHClient()
        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.ss_host, username=self.ss_user, password=self.ss_password)

            if self.method == "ssperl":
                #addming the configuration
                message.append("adding auto_grouping rule: " + self.group_info["name"])
                (stdin, stdout, stderr) = client.exec_command(pre_command + "ssperl -e " + auto_group_command, get_pty=True)
                error = stderr.read()
                output = stdout.read()

                if error or stdout.channel.recv_exit_status():
                    raise ERROR_exception(error + output)
                else:
                    message.append("success")

            # Close parmiko client
            client.close()

        # Exception handeling
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


#
# ss_cr_import: importing a custom reporting configuration to a statseeker server
#

class ss_cr_import(base.statseeker_base):
    description = "This module imports a custom reporting configuration to a statseeker server"
    
    def __init__(self, host, ss_user, ss_password, tmp_config, report_name):
        super(ss_cr_import, self).__init__("ss_cr_import", "4.x/5.x")
        self.ss_host = host
        self.ss_user = ss_user
        self.ss_password = ss_password
        self.tmp_config = tmp_config
        self.report_name = report_name
    
    def rm_emp_line(self, string):
        return filter(lambda x: not re.match(r'^\s*$', x), string)


    def main(self):
        message = []
        
        # verify the template is valid
        if not os.path.isfile(self.tmp_config):
            raise ERROR_exception("the template configuration is not file")
        else:
            try:
                with open(self.tmp_config) as f:
                    data_dict = json.load(f)
            except ValueError as e:
                raise ERROR_exception("the template config is not valid json")

        data_encode = urllib2.quote(json.dumps(data_dict))
        client = paramiko.SSHClient()
        
        # load the ~/.profile before running commands nop, not for statseeker
        pre_command = ". ~/.profile;"

        try:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.ss_host, username=self.ss_user, password=self.ss_password)
            
            # run first cgi query to add config
            cgi_config = "REMOTE_USER='admin' QUERY_STRING='' REQUEST_METHOD='' /usr/local/statseeker/ss/cgi/crtool 'mode=save&name=" + self.report_name + "&data=" + data_encode + "'"
            message.append("adding the custom report configuration")
            (stdin, stdout, stderr) = client.exec_command(pre_command + cgi_config, get_pty=True)
            error = stderr.read()
            output = json.loads(stdout.read().split('\n')[-1])["msgs"][0]

            if error or stdout.channel.recv_exit_status():
                raise ERROR_exception(error + output)
            elif output["state"] == "success":
                message.append("success")
            else:
                raise ERROR_exception(output["msg"])

            # get report id
            get_id = "base-ega get report info \'\"C00:Custom Reports: " + self.report_name + "\"\' | cut -f2 -d \\'"
            message.append("geting the report id using base ega")
            (stdin, stdout, stderr) = client.exec_command(pre_command + get_id, get_pty=True)
            error = stderr.read()
            output = stdout.read()

            if error or stdout.channel.recv_exit_status():
                raise ERROR_exception(error + output)
            else:
                message.append("success")
                report_id = self.rm_emp_line(output)
            
            # get append to report list
            list_append = "REMOTE_USER='admin' REQUEST_METHOD='' /usr/local/statseeker/ss/cgi/crtool 'mode=modify-list&user=admin&cmd=add&id=" + report_id + "&name=" + self.report_name + "&parent=#&type=report'"
            message.append("adding to report list")
            (stdin, stdout, stderr) = client.exec_command(pre_command + list_append, get_pty=True)
            error = stderr.read()
            output = json.loads(stdout.read().split('\n')[-1])["msgs"][0]

            if error or stdout.channel.recv_exit_status():
                raise ERROR_exception(error + output)
            elif output["state"] == "success":
                message.append("success")
            else:
                raise ERROR_exception(output["msg"])

            # Close parmiko client
            client.close()

        # Exception handeling
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


#
# ss_report_import: importing a custom reporting configuration to a statseeker server
#

class ss_report_import(base.statseeker_base):
    description = "This module imports a custom reporting configuration to a statseeker server"
    
    def __init__(self, host, ss_user, ss_password, config_dir):
        super(ss_report_import, self).__init__("ss_report_import", "4.x/5.x")
        self.ss_host = host
        self.ss_user = ss_user
        self.ss_password = ss_password
        self.config_dir = config_dir
    
    def rm_emp_line(self, string):
        return filter(lambda x: not re.match(r'^\s*$', x), string)

    def file_check(self, config):
        if not os.path.isfile(config):
            return False
        else:
            try:
                with open(config) as f:
                    data_dict = json.load(f)
            except ValueError as e:
                return False
            else:
                return True

    def main(self):
        message = []
        warn = []

        try:
            # verify the template is valid
            if not os.path.isdir(self.config_dir):
                raise ERROR_exception("given directory is not valid")
            elif not os.path.isfile(self.config_dir + "custom-report-list-admin.cfg"):
                raise ERROR_exception("no admin list found")

            # load the ~/.profile before running commands nop, not for statseeker
            pre_command = ". ~/.profile;"

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.ss_host, username=self.ss_user, password=self.ss_password)
           
            # read in old id/name pair
            name_id_dict = {}
           
            # constructing the name old/new id look up dict
            message.append("constructing the name old/new id look up dict")
            with open(self.config_dir + "custom-report-list-admin.cfg", "r") as f:
                admin_config_dict = json.load(f)
            
            for report_entry in admin_config_dict["nodes"]:
                if report_entry["id"].isdigit():
                    name_id_dict[report_entry["text"]] = {}
                    name_id_dict[report_entry["text"]]["old_id"] = report_entry["id"]
            
                    # base-ega add report 
                    ega_add = "base-ega add report \'\"C00:Custom Reports: " + report_entry["text"]+ "\"\' | cut -f2 -d \\'"
                    (stdin, stdout, stderr) = client.exec_command(pre_command + ega_add, get_pty=True)
                    error = stderr.read()
                    output = stdout.read()

                    if error or stdout.channel.recv_exit_status():
                        raise ERROR_exception(error + output)
                    else:
                        name_id_dict[report_entry["text"]]["new_id"] = self.rm_emp_line(output)

                else:
                    warn.append(report_entry["text"] + " is ignored")
            message.append("success") 

            # update ids in the existing config
            for config_file in os.listdir(self.config_dir):

                # updating report configs
                if re.search("nim-custom-report", config_file):

                    with open(self.config_dir + config_file, 'r') as f:
                        report_config_dict = json.load(f)
                    
                    # replace the report id
                    report_name = report_config_dict["name"]
                    report_config_dict["id"] = name_id_dict[report_name]["new_id"]

                    file_name = "nim-custom-report-" + name_id_dict[report_name]["new_id"]

                    # write the report cfg to new file
                    sftp = client.open_sftp()
                    ss_report_config = "/home/statseeker/nim/etc/customreports/" + file_name

                    with sftp.open(ss_report_config, "w") as f:
                        f.write(json.dumps(report_config_dict))

                # updating report list
                elif re.search("custom-report-list", config_file):
                    file_name = config_file
                    
                    with open(self.config_dir + config_file, 'r') as f:
                        report_list_dict = json.load(f)
                    
                    for report_entry in admin_config_dict["nodes"]:
                        
                        if report_entry["id"].isdigit() and report_entry["text"] in name_id_dict:
                                report_entry["id"] = name_id_dict[report_entry["text"]]["new_id"]
                        else:
                            # filter out invalid entries
                            del report_entry

                    # write the report list to new file
                    sftp = client.open_sftp()
                    ss_list_config = "/home/statseeker/nim/etc/customreports/" + file_name

                    with sftp.open(ss_list_config, "w") as f:
                        f.write(json.dumps(report_list_dict))

            # Close parmiko client
            client.close()

        # Exception handeling
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


