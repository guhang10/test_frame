#!/usr/local/bin/python2.7

#
# This file defines all types of bases that will be used in the test frame work, all tasks will inherit from
# their corresponding types of bases. The predefined types of bases are:

# pyvmomi_base: base that is intended to be used by tasks that are interpreted into pyvmomi commands
# ansible_base: this base type will run a ansible script on a remote machine
# script_base: base that runs scripts on remote hosts and collect extra information (for configuration scripts,use ansible_base to deploy)
# local_base: this base type if for modules to be run locally

# deployment will be arranged differently depending on which base the tasks and subtasks inherits (what if multiple?)
# Each module will have a globle id (module_id) and a category id (module_xxx_id), each module will also contain the intended statseeker version of the module
#

import errno
import os

module_id = 0
module_local_id = 0
module_vmware_id = 0
module_ansible_id = 0
module_script_id = 0
module_statseeker_id = 0

class base(object):
    
    def __init__(self, name, version):
        self.name = name
        self.version = version
        
        global module_id 
        self.module_id = module_id
        module_id += 1


class local_base(base):

    def __init__(self, name, version):
        super(local_base, self).__init__(name, version)
        self.base_type = "local"

        global module_local_id 
        self.module_local_id = module_local_id
        module_local_id += 1


class vmware_base(base):

    def __init__(self, name, version):
        super(vmware_base, self).__init__(name, version)
        self.base_type = "vmware"

        global module_vmware_id 
        self.module_vmware_id = module_vmware_id
        module_vmware_id += 1


class ansible_base(base):

    def __init__(self, name, version):
        super(ansible_base, self).__init__(name, version)
        self.base_type = "ansible"

        global module_ansible_id 
        self.module_ansible_id = module_ansible_id
        module_ansible_id += 1


class script_base(base):

    def __init__(self, name, version, file_location):
        super(script_base, self).__init__(name, version)
        self.base_type = "script"
        self.local = file_location

        global module_script_id 
        self.module_script_id = module_script_id
        module_script_id += 1

        self.script_type = self.local.split(".")[-1]
        self.script_md5 = None

    def check_location(self):
        if os.path.isfile(self.local):
            pass
        else:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), filename)

        
class ssh_base(base):

    def __init__(self, name, version):
        super(ssh_base, self).__init__(name, version)
        self.base_type = "ssh"

        global module_ssh_id 
        self.module_ssh_id = module_ssh_id
        module_ssh_id += 1


class statseeker_base(base):

    def __init__(self, name, version):
        super(statseeker_base, self).__init__(name, version)
        self.base_type = "statseeker"

        global module_statseeker_id 
        self.module_statseeker_id = module_statseeker_id
        module_statseeker_id += 1

