# This file contains all the test realted to vmware application
# It will follow the same convention, all modules must inherit from vmware_base and coantains a main function

import base
import atexit
import ssl
import json
import meta
import time
import requests
import warnings
from vm_tools import tasks
import subprocess
import os

from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim

#
# Custom exception
#

class ERROR_exception(Exception):
        def __init__(self, msg):
            self.msg = msg

#
# vmware_connect_test module
#

class vmware_connect_test(base.vmware_base):
    description = "testing the connection between local host and vmware host"

    def __init__(self, host, user, password):
        super(vmware_connect_test, self).__init__("vmware_conncet_test", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password

    def main(self):
        
        return_dict = {}
        message = []

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

        except Exception as e:
            print e
            return_dict["success"] = "False"
            meta_dict = meta.meta_header(host=self.host, user=self.user, ERROR=error.msg)
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)
        
        else:
            return_dict["success"] = "True"
            meta_dict = meta.meta_header(host=self.host, user=self.user)
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)
            

#
# vmware_get_vms module
#

class vmware_get_vms(base.vmware_base):
    description = "show all vms on a vmware host"

    def __init__(self, host, user, password, json):
        super(vmware_get_vms, self).__init__("vmware_get_vms", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.json = json

    def print_vm_info(self, virtual_machine):
        """
        Print information for a particular virtual machine or recurse into a
        folder with depth protection
        """
        summary = virtual_machine.summary
        print("Name       : ", summary.config.name)
        print("Template   : ", summary.config.template)
        print("Path       : ", summary.config.vmPathName)
        print("Guest      : ", summary.config.guestFullName)
        print("Instance UUID : ", summary.config.instanceUuid)
        print("Bios UUID     : ", summary.config.uuid)
        annotation = summary.config.annotation
        if annotation:
            print("Annotation : ", annotation)
        print("State      : ", summary.runtime.powerState)
        if summary.guest is not None:
            ip_address = summary.guest.ipAddress
            tools_version = summary.guest.toolsStatus
            if tools_version is not None:
                print("VMware-tools: ", tools_version)
            else:
                print("Vmware-tools: None")
            if ip_address:
                print("IP         : ", ip_address)
            else:
                print("IP         : None")
        if summary.runtime.question is not None:
            print("Question  : ", summary.runtime.question.text)
        print("")

    def construct_dict(self, virtual_machine):
        """
        construct part of a json string, it's then concatenated to the VMS dictionary

        """

        summary = virtual_machine.summary
        vm = {}
        vm["Name"] = summary.config.name
        vm["Template"] = summary.config.template
        vm["Path"] = summary.config.vmPathName
        vm["Guest"] = summary.config.guestFullName
        vm["Instance UUID"] = summary.config.instanceUuid
        vm["Bios UUID"] = summary.config.uuid

        if summary.config.annotation:
            vm["Annotation"] = summary.config.annotation

        vm["State"] = summary.runtime.powerState

        if summary.guest.toolsStatus:
            vm["VMware-tools"] = summary.guest.toolsStatus

        if summary.guest.ipAddress:
            vm["IP"] = summary.guest.ipAddress
        else:
            vm["IP"] = None

        if summary.runtime.question is not None:
            vm["Question"] = summary.runtime.question.text

        return vm


    def main(self):
        message = []
        return_dict = {}
        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            content = service_instance.RetrieveContent()
            container = content.rootFolder  # Starting point to look into
            viewType = [vim.VirtualMachine] # Object types to look for
            recursive = True 
            containerView = content.viewManager.CreateContainerView(
                    container, viewType, recursive)

            children = containerView.view

            return_dict["result"] = []

            for child in children:

                if not self.json:
                    self.print_vm_info(child)

                else:
                    return_dict["result"].append(self.construct_dict(child))


        except vmodl.MethodFault as e:
            print("Caught vmodl fault : " + e.msg)
            
            if self.json:
                return_dict["success"] = "False"
                message = "oops"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main() 
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return False
        
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True
            

#
# vmware_poweroff_vm module
#

class vmware_poweroff_vm(base.vmware_base):
    description = "power off a vm"

    def __init__(self, host, user, password, json, **search):
        super(vmware_poweroff_vm, self).__init__("vmware_poweroff_vm", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.search = search
        self.json = json

    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj


    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            return_dict = {}

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "ip" in self.search:
                VM = service_instance.content.searchIndex.FindByIp(None, self.search["ip"], True)

            elif "domain_name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["domain_name"],
                                                                        True)
            elif "name" in self.search:
                content = service_instance.RetrieveContent()
                VM = self.get_obj(content, [vim.VirtualMachine], self.search["name"])

            else:
                raise ERROR_exception("No valid search criteria given")

            if VM is None:
                raise ERROR_exception("Unable to locate VirtualMachine.")

            message = []

            message.append("Found: {0}".format(VM.name))
            message.append("The current powerState is: {0}".format(VM.runtime.powerState))
            message.append("Attempting to power off {0}".format(VM.name))

            if not self.json:
                for i in message[0:3]: print i

            TASK = VM.PowerOffVM_Task()
            tasks.wait_for_tasks(service_instance, [TASK])

            message.append("{0}".format(TASK.info.state))
            message.append("The current powerState is: {0}".format(VM.runtime.powerState))

            if not self.json:
                for i in message[3:5]: print i
         
        #   exception capture

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
        
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True
            
   
#
# vmware_poweron_vm module: this module will not accept ipaddress as filter, off machines don't have ip field
#

class vmware_poweron_vm(base.vmware_base):
    description = "power on a vm"

    def __init__(self, host, user, password, json, **search):
        super(vmware_poweron_vm, self).__init__("vmware_poweron_vm", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.search = search
        self.json = json

    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj


    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)
            
            return_dict = {}
            message = []

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "domain_name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["domain_name"],
                                                                        True)
            elif "name" in self.search:
                content = service_instance.RetrieveContent()
                VM = self.get_obj(content, [vim.VirtualMachine], self.search["name"])

            else:
                raise ERROR_exception("No valid search criteria given")

            if VM is None:
                raise ERROR_exception("Unable to locate VirtualMachine.")

            message.append("Found: {0}".format(VM.name))
            message.append("The current powerState is: {0}".format(VM.runtime.powerState))
            message.append("Attempting to power on {0}".format(VM.name))

            if not self.json:
                for i in message[0:3]: print i

            TASK = VM.PowerOnVM_Task()
            tasks.wait_for_tasks(service_instance, [TASK])

            message.append("{0}".format(TASK.info.state))
            message.append("The current powerState is: {0}".format(VM.runtime.powerState))

            if not self.json:
                for i in message[3:5]: print i
         
         #   exception capture

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
            
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True
         
       
#
# vmware_delete_vm module
#
  
class vmware_delete_vm(base.vmware_base):
    description = "delete a vm"

    def __init__(self, host, user, password, json, **search):
        super(vmware_delete_vm, self).__init__("vmware_delete_vm", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.search = search
        self.json = json

    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj


    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)
            
            return_dict = {}
            message = []

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "ip" in self.search:
                VM = service_instance.content.searchIndex.FindByIp(None, self.search["ip"], True)

            elif "domain_name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["domain_name"],
                                                                        True)
            elif "name" in self.search:
                content = service_instance.RetrieveContent()
                VM = self.get_obj(content, [vim.VirtualMachine], self.search["name"])

            else:
                raise ERROR_exception("No valid search criteria given")

            if VM is None:
                raise ERROR_exception("Unable to locate VirtualMachine.")

            message.append("Found: {0}".format(VM.name))
            message.append("The current powerState is: {0}".format(VM.runtime.powerState))

            if not self.json:
                for i in message[0:2]: print i

            if VM.runtime.powerState != "poweredOff":
                message.append("Attempting to power off {0}".format(VM.name))

                TASK = VM.PowerOffVM_Task()
                tasks.wait_for_tasks(service_instance, [TASK])
            
                message.append("{0}".format(TASK.info.state))
                message.append("The current powerState is: {0}".format(VM.runtime.powerState))

                if not self.json:
                    for i in message[-3: -1]: print i

            message.append("Attempting to delete {0}".format(VM.name))
            
            TASK = VM.Destroy_Task()
            tasks.wait_for_tasks(service_instance, [TASK])
            
            message.append("{0}".format(TASK.info.state))
            
            if not self.json:
                for i in message[-2: -1]: print i
            
          #   exception capture

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
            
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True
            

#
# vmware_reset_vm module: this module reset a vm (hard reset)
#

class vmware_reset_vm(base.vmware_base):
    description = "hard reset a vm"

    def __init__(self, host, user, password, json, **search):
        super(vmware_reset_vm, self).__init__("vmware_reset_vm", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.json = json
        self.search = search

    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj


    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            return_dict = {}
            message = []

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "ip" in self.search:
                VM = service_instance.content.searchIndex.FindByIp(None, self.search["ip"], True)

            elif "domain_name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["domain_name"],
                                                                        True)
            elif "name" in self.search:
                content = service_instance.RetrieveContent()
                VM = self.get_obj(content, [vim.VirtualMachine], self.search["name"])

            else:
                raise ERROR_exception("No valid search criteria given")

            if VM is None:
                raise ERROR_exception("Unable to locate VirtualMachine.")

            message.append("Found: {0}".format(VM.name))
            message.append("The current powerState is: {0}".format(VM.runtime.powerState))
            message.append("Attempting to reset {0}".format(VM.name))
            TASK = VM.ResetVM_Task()
            tasks.wait_for_tasks(service_instance, [TASK])
            message.append("{0}".format(TASK.info.state))

            if not self.json:
                for i in message: 
                    print i

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
        
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True
            

#
# vmware_soft_reboot_vm module: this module send target vm a  reboot signal(no gurantee for a reboot though)
#

class vmware_soft_reboot_vm(base.vmware_base):
    description = "send vm a soft reboot signal"

    def __init__(self, host, user, password, json, **search):
        super(vmware_soft_reboot_vm, self).__init__("vmware_soft_reboot_vm", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.search = search
        self.json = json

    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj


    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            return_dict = {}
            message = []

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "ip" in self.search:
                VM = service_instance.content.searchIndex.FindByIp(None, self.search["ip"], True)

            elif "domain_name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["domain_name"],
                                                                        True)
            elif "name" in self.search:
                content = service_instance.RetrieveContent()
                VM = self.get_obj(content, [vim.VirtualMachine], self.search["name"])

            else:
                raise ERROR_exception("No valid search criteria given")

            if VM is None:
                raise ERROR_exception("Unable to locate VirtualMachine.")

                       
            message.append("Found: {0}".format(VM.name))
            message.append("The current powerState is: {0}".format(VM.runtime.powerState))
            message.append("Attempting to reboot {0}".format(VM.name))

            TASK = VM.RebootGuest()
            tasks.wait_for_tasks(service_instance, [TASK])
            
            if not self.json: 
                for i in message: 
                    print i

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
            
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True
            
        
#
#  wmare_list_datastore_info module: still haven't decide whether I want json output yet (definitely)
#

class vmware_list_datastore_info(base.vmware_base):
    description = "list datastore informations"

    def __init__(self, host, user, password, json):
        super(vmware_list_datastore_info, self).__init__("vmware_list_datastore_info", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.json = json

    def sizeof_fmt(self, num):
        """
        Returns the human readable version of a file size

        :param num:
        :return:
        """
        for item in ['bytes', 'KB', 'MB', 'GB']:
            if num < 1024.0:
                return "%3.1f%s" % (num, item)
            num /= 1024.0
        return "%3.1f%s" % (num, 'TB')


    def print_fs(self, host_fs):
        """
        Prints the host file system volume info

        :param host_fs:
        :return:
        """
        print("{}\t{}\t".format("Datastore:     ", host_fs.volume.name))
        print("{}\t{}\t".format("UUID:          ", host_fs.volume.uuid))
        print("{}\t{}\t".format("Capacity:      ", self.sizeof_fmt(
            host_fs.volume.capacity)))
        print("{}\t{}\t".format("VMFS Version:  ", host_fs.volume.version))


    def main(self):

        message = []
        return_dict = {}

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            
            if not service_instance:
                if not self.json:
                    print("could not connect ot the host with given credentials")
                    return False
                else:
                    raise ERROR_exception("could not connect ot the host with given credentials")
            else:
                message.append("connection to " + self.host + " established")

            content = service_instance.RetrieveContent()

            objview = content.viewManager.CreateContainerView(content.rootFolder,
                                                          [vim.HostSystem],
                                                          True)
            esxi_hosts = objview.view
            objview.Destroy()

            datastores = {}

            for esxi_host in esxi_hosts:
                if not self.json:
                    print("{}\t{}\t\n".format("ESXi Host:    ", esxi_host.name))

                # All Filesystems on ESXi host
                storage_system = esxi_host.configManager.storageSystem
                host_file_sys_vol_mount_info = \
                    storage_system.fileSystemVolumeInfo.mountInfo

                datastore_dict = {}
                # Map all filesystems
                for host_mount_info in host_file_sys_vol_mount_info:
                    # Extract only VMFS volumes
                    if host_mount_info.volume.type == "VMFS":

                        extents = host_mount_info.volume.extent
                        if not self.json:
                            self.print_fs(host_mount_info)
                        else:
                            datastore_details = {
                                'uuid': host_mount_info.volume.uuid,
                                'capacity': host_mount_info.volume.capacity,
                                'vmfs_version': host_mount_info.volume.version,
                                'local': host_mount_info.volume.local,
                                'ssd': host_mount_info.volume.ssd
                            }

                        extent_arr = []
                        extent_count = 0
                        for extent in extents:
                            if not self.json:
                                print("{}\t{}\t".format(
                                    "Extent[" + str(extent_count) + "]:",
                                    extent.diskName))
                                extent_count += 1
                            else:
                                # create an array of the devices backing the given
                                # datastore
                                extent_arr.append(extent.diskName)
                                # add the extent array to the datastore info
                                datastore_details['extents'] = extent_arr
                                # associate datastore details with datastore name
                                datastore_dict[host_mount_info.volume.name] = \
                                    datastore_details
                        if not self.json:
                            print

                # associate ESXi host with the datastore it sees
                datastores[esxi_host.name] = datastore_dict

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
            
        else:
            if self.json:
                return_dict["success"] = "True"
                return_dict["result"] = datastores
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True


#
# vmware_clone_vm: this modue is designed to clone an existing vm (how is ip address and uuid resolved? DHCP)
# clone a vm is okay, but not permitted to power it up, duplicated ip maybe, need to modify
#

class vmware_clone_vm(base.vmware_base):
    description = "this modue is designed to clone an existing vm (how is ip address and uuid resolved?)"

    def __init__(self, host, user, password, json, vm_name, template, **select):
        super(vmware_clone_vm, self).__init__("vmware_clone_vm", "6.0.0")
       
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        
        self.host = host
        self.user = user
        self.password = password
        self.json = json
        self.vm_name = vm_name
        self.template = template
        self.select = select

        elective = ["datacenter_name", "vm_folder", "datastore_name", "cluster_name", "resource_pool",
                    "power_on"]

        for var in elective:
            if var in select:
                setattr(self, var, self.select[var])
            else:
                setattr(self, var, None)


    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj


    def clone_vm(
            self, content, template, vm_name, service_instance,
            datacenter_name, vm_folder, datastore_name,
            cluster_name, resource_pool, power_on):
        """
        Clone a VM from a template/VM, datacenter_name, vm_folder, datastore_name
        cluster_name, resource_pool, and power_on are all optional.
        """

        # if none git the first one
        datacenter = self.get_obj(content, [vim.Datacenter], datacenter_name)

        if vm_folder:
            destfolder = self.get_obj(content, [vim.Folder], vm_folder)
        else:
            destfolder = datacenter.vmFolder

        if datastore_name:
            datastore = self.get_obj(content, [vim.Datastore], datastore_name)
        else:
            datastore = self.get_obj(
                content, [vim.Datastore], template.datastore[0].info.name)

        # if None, get the first one
        cluster = self.get_obj(content, [vim.ClusterComputeResource], cluster_name)

        if resource_pool:
            resource_pool = self.get_obj(content, [vim.ResourcePool], resource_pool)
        else:
            resource_pool = cluster.resourcePool

        # set customspec
        # guest NIC settings, i.e. "adapter map"
        adaptermaps=[]
        guest_map = vim.vm.customization.AdapterMapping()
        guest_map.adapter = vim.vm.customization.IPSettings()
        guest_map.adapter.ip = vim.vm.customization.FixedIp()
        guest_map.adapter.ip.ipAddress = "10.2.26.158"
        guest_map.adapter.subnetMask = "255.255.255.0"
        adaptermaps.append(guest_map)
        
        # Hostname settings only supports windows and linux bloody hell!
        ident = vim.vm.customization.LinuxPrep()
        ident.domain = "statseeker.com"
        ident.hostName = vim.vm.customization.FixedName()
        ident.hostName.name = vm_name

        # DNS settings
        globalip = vim.vm.customization.GlobalIPSettings()
        globalip.dnsServerList = "10.1.5.2"
        globalip.dnsSuffixList = "statseeker.com"

        customspec = vim.vm.customization.Specification()
        customspec.nicSettingMap = adaptermaps
        customspec.identity = ident
        customspec.globalIPSettings = globalip

        # set relospec
        relospec = vim.vm.RelocateSpec()
        relospec.datastore = datastore
        relospec.pool = resource_pool

        # set clonespec, note custom spec is required to change ip and domain name
        clonespec = vim.vm.CloneSpec()
        clonespec.location = relospec
        clonespec.powerOn = power_on
        clonespec.template = False
        #clonespec.config = vmconf

        #customization of freebsd vms are not supported in vmware as for now, power_on stays False
        #when cloning from vm instead of template
        #clonespec.customization = customspec 
        
        print "cloning VM..."

        TASK = template.Clone(folder=destfolder, name=vm_name, spec=clonespec)

        tasks.wait_for_tasks(service_instance, [TASK])

    
    def main(self):

        return_dict = {}
        message = []

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            content = service_instance.RetrieveContent()
            # template is not a template, it should be able to be a vm as well, fingers crossed
            # is this name the dns name or vm name (need to find out)
            template = self.get_obj(content, [vim.VirtualMachine], self.template)

            if template:
                message.append("Found vm template: " + self.template)
                self.clone_vm(content, template, self.vm_name, service_instance, self.datacenter_name,
                        self.vm_folder, self.datastore_name, self.cluster_name, self.resource_pool,
                        self.power_on)
                       
            else:
                raise ERROR_exception("Can't find specified template")

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dect["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
        
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dect["message"] = message
                return json.dumps(return_dict)
            else:
                return True



#
# vmware_create_vm: this module creates a new vm 
#

class vmware_create_vm(base.vmware_base):
    description="This module is used to create new vm"

    def __init__(self, host, user, password, json, vm_name, datastore, **settings):
        super(vmware_create_vm, self).__init__("vmware_create_vm", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.json = json
        self.vm_name = vm_name
        self.datastore = datastore
        self.settings = settings

    def main(self):
        
        return_dict = {}
        message = []

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            content = service_instance.RetrieveContent()
            datacenter = content.rootFolder.childEntity[1]
            vm_folder = datacenter.vmFolder
            hosts = datacenter.hostFolder.childEntity
            resource_pool = hosts[0].resourcePool

            # define datastore file path
            datastore_path = '[' + self.datastore +']' + self.vm_name

            #creating parameter dictionary
            param = {}
            param["name"] = self.vm_name
            param["files"] = vim.vm.FileInfo(logDirectory=None,
                                 snapshotDirectory=None,
                                 suspendDirectory=None,
                                 vmPathName=datastore_path)
            
            # default setting
            param["memoryMB"] = 1024
            param["numCPUs"] = 1
            param["guestId"] = "freebsd64Guest"
            param["version"] = "vmx-07"
            
            # overwrite and append to default setting by "self.settings"
            for setting in self.settings:
                param[setting] = self.settings[setting]
            
            # Set config spec
            config = vim.vm.ConfigSpec(**param)

            message.append("Creating VM {}...".format(self.vm_name))

            if not self.json:
                print message[0]

            task = vm_folder.CreateVM_Task(config=config, pool=resource_pool)
            tasks.wait_for_tasks(service_instance, [task])

            # use some of the params as a returned result, excluding files though
            del param["files"]
            return_dict["result"] = param
        
        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
        
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True



#
# vmware_add_disk: this module add a hard disk to a vm, if the vm does not have a 
# logic controller, the module will add one automatically
#

class vmware_add_disk(base.vmware_base):
    description = "This module is designed to add hard disks to existing vms"

    def __init__(self, host, user, password, json, vm_name, disk_type, disk_size, **select):
        super(vmware_add_disk, self).__init__("vmware_add_disk", "6.0.0")
       
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        
        self.host = host
        self.user = user
        self.password = password
        self.json = json
        self.vm_name = vm_name
        self.disk_type = disk_type
        self.disk_size = disk_size
        self.select = select

    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj

    # adding a controller
    def add_controller(self, vm, service_instance):
        task = vm.ReconfigVM_Task(
            spec=vim.vm.ConfigSpec(
                deviceChange=[
                    vim.vm.device.VirtualDeviceSpec(
                        operation=vim.vm.device.VirtualDeviceSpec.Operation.add,
                        device=vim.vm.device.VirtualLsiLogicSASController(
                            sharedBus=vim.vm.device.VirtualSCSIController.Sharing.noSharing
                        ),
                    )
                ]
            )
        )

        tasks.wait_for_tasks(service_instance, [task])
        return "Added SCS logic controller to vm"


    # checking disk and controller
    def device_check(self, vm):
        unit_number = 0
        controller = None
        # get all disks on a VM, set unit_number to the next available
        for dev in vm.config.hardware.device:
            if hasattr(dev.backing, 'fileName'):
                unit_number = int(dev.unitNumber) + 1
                # unit_number 7 reserved for scsi controller
                if unit_number == 7:
                    unit_number += 1
                if unit_number >= 16:
                    raise ERROR_exception("Does not support more devices")
            # checking existing controller
            if isinstance(dev, vim.vm.device.VirtualSCSIController):
                controller = dev
        return {"unit_number": unit_number, "controller": controller}

    
    # adding a disk, if there is no controller, add a controller first 
    def add_disk(self, vm, service_instance, disk_size, disk_type):
        return_message = []
        
        check = self.device_check(vm)
        controller = check["controller"]
        unit_number = check["unit_number"]

        while not (controller and isinstance(unit_number , int)):
         # add controller here
            return_message.append(self.add_controller(vm, service_instance))
            check = self.device_check(vm)
            controller = check["controller"]
            unit_number = check["unit_number"]

        spec = vim.vm.ConfigSpec()
        dev_changes = []
        new_disk_kb = int(disk_size) * 1024 * 1024
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.fileOperation = "create"
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.backing = \
            vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        if disk_type == 'thin':
            disk_spec.device.backing.thinProvisioned = True
        disk_spec.device.backing.diskMode = 'persistent'
        disk_spec.device.unitNumber = unit_number
        disk_spec.device.capacityInKB = new_disk_kb
        disk_spec.device.controllerKey = controller.key
        dev_changes.append(disk_spec)
        spec.deviceChange = dev_changes

        task = vm.ReconfigVM_Task(spec=spec)
        tasks.wait_for_tasks(service_instance, [task])

        return_message.append("%sGB disk added to %s" % (disk_size, vm.config.name))
        #return_message.append(str(task.info))
        return return_message
        
    def main(self):

        return_dict = {}
        message = []

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            content = service_instance.RetrieveContent()
            # template is not a template, it should be able to be a vm as well, fingers crossed
            # is this name the dns name or vm name (need to find out)
            vm = self.get_obj(content, [vim.VirtualMachine], self.vm_name)

            if vm:
                message.append("Found vm: " + self.vm_name)
                message.append(self.add_disk(vm, service_instance, self.disk_size, self.disk_type))

            else:
                raise ERROR_exception("Can't find specified vm")

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
            
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True


#
# vmware_add_nic: this module add a network card to an existing vm, nic type should be configurable
# the net work adapter name need to increment every time a new network adapter is added 
# this is because multiple network may be added for ha installation
#

class vmware_add_nic(base.vmware_base):
    description = "This module is designed to add nic to existing vms"

    def __init__(self, host, user, password, json, vm_name, network, **select):
        super(vmware_add_nic, self).__init__("vmware_add_disk", "6.0.0")
       
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        
        self.host = host
        self.user = user
        self.password = password
        self.json = json
        self.vm_name = vm_name
        self.network = network
        self.select = select

    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj


    # checking disk and controller
    def device_check(self, vm):
        unit_number = 0
        # get all devices on a VM, set unit_number to the next available
        for dev in vm.config.hardware.device:
            if hasattr(dev.backing, 'fileName'):
                unit_number = int(dev.unitNumber) + 1
                # unit_number 7 reserved for scsi controller
                if unit_number == 7:
                    unit_number += 1
                if unit_number >= 16:
                    raise ERROR_exception("Does not support more devices")
        return unit_number

    
    # adding a network card
    def add_nic(self, vm, service_instance, network):
        return_message = []

        unit_number = self.device_check(vm)

        spec = vim.vm.ConfigSpec()
        nic_changes = []

        nic_spec = vim.vm.device.VirtualDeviceSpec()
        nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add

        # the nic type is defaulted to VirtualE1000
        if "type" not in self.select:
            nic_spec.device = vim.vm.device.VirtualE1000()
        elif self.select["type"] == "E1000":
            nic_spec.device = vim.vm.device.VirtualE1000()
        elif self.select["type"] == "VMXNET3":
            nic_spec.device = vim.vm.device.VirtualVmxnet3()
        elif self.select["type"] == "VMXNET2":
            nic_spec.device = vim.vm.device.VirtualVmxnet2()
        else:
            raise ERROR_exception("The type given for nic is not valid")

        nic_spec.device.key = 4009

        nic_spec.device.deviceInfo = vim.Description()
        #nic_spec.device.deviceInfo.label = 'Network adapter 10'
        #nic_spec.device.deviceInfo.summary = 'network'

        nic_spec.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
        nic_spec.device.backing.useAutoDetect = False

        # retrieve the content here again is a lazy solution, come back to fix later
        content = service_instance.RetrieveContent()
        nic_spec.device.backing.network = self.get_obj(content, [vim.Network], network)
        nic_spec.device.backing.deviceName = network

        nic_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        nic_spec.device.connectable.startConnected = True
        nic_spec.device.connectable.allowGuestControl = True
        nic_spec.device.connectable.connected = False
        nic_spec.device.connectable.status = 'untried'
        nic_spec.device.controllerKey = 100
        nic_spec.device.wakeOnLanEnabled = True
        nic_spec.device.addressType = 'assigned'


        nic_changes.append(nic_spec)

        spec.deviceChange = nic_changes

        task = vm.ReconfigVM_Task(spec=spec)
        tasks.wait_for_tasks(service_instance, [task])

        #return_message.append(str(task.info))
        return_message.append("added network interface card to: " + network)
        return return_message
                        
    def main(self):

        return_dict = {}
        message = []

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            content = service_instance.RetrieveContent()
            # template is not a template, it should be able to be a vm as well, fingers crossed
            # is this name the dns name or vm name (need to find out)
            vm = self.get_obj(content, [vim.VirtualMachine], self.vm_name)

            if vm:
                message.append("Found vm: " + self.vm_name)
                message.append(self.add_nic(vm, service_instance, self.network))

            else:
                raise ERROR_exception("Can't find specified vm")

        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
           
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True


#
# vmware_add_cdrom: this module attach a cdrom to a vm
#
class vmware_add_cdrom(base.vmware_base):
    description = "This module is used to configure a cdrom (install, delete and connect)"

    def __init__(self, host, user, pwd, json, vm_name, cdrom_name, **elective):
        super(vmware_add_cdrom, self).__init__("vmware_add_cdrom", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE

        self.host = host
        self.user = user
        self.password = pwd
        self.json = json
        self.vm_name = vm_name
        self.cdrom_name = cdrom_name
        self.elective = elective
        
        self.physical = None
        self.iso = None

        for item in self.elective:
            setattr(self, item, self.elective[item])

    # this get_obj is only used to search for vm here, might need to merge some of the 
    # functions a little bit later
    def get_obj(self, content, vimtype, name):
            """
            Return an object by name, if name is None the
            first found object is returned
            """
            obj = None
            container = content.viewManager.CreateContainerView(
                content.rootFolder, vimtype, True)
            for c in container.view:
                if name:
                    if c.name == name:
                        obj = c
                        break
                else:
                    obj = c
                    break

            return obj


    # get datacenter, we will need in the future
    def get_dc(self, si, name):
        for dc in si.content.rootFolder.childEntity:
            if dc.name == name:
                return dc
        raise Exception('Failed to find datacenter named %s' % name)

    # return the first physical cdrom if any
    def get_physical_cdrom(self, host):
        for lun in host.configManager.storageSystem.storageDeviceInfo.scsiLun:
            if lun.lunType == 'cdrom':
                return lun
        return None
    
    # find_free_ide_controller(vm): if none is find, we need to create one
    def find_free_ide_controller(self, vm):
        for dev in vm.config.hardware.device:
            if isinstance(dev, vim.vm.device.VirtualIDEController):
                # If there are less than 2 devices attached, we can use it.
                if len(dev.device) < 2:
                    return dev
        return None

    # find devices (of a certain type) that belong to a vm
    def find_device(self, vm, device_type):
        result = []
        for dev in vm.config.hardware.device:
            if isinstance(dev, device_type):
                result.append(dev)
        return result

    # define the new cdrom spec
    def new_cdrom_spec(self, controller_key, backing):
        connectable = vim.vm.device.VirtualDevice.ConnectInfo()
        connectable.allowGuestControl = True
        connectable.startConnected = True

        cdrom = vim.vm.device.VirtualCdrom()
        cdrom.controllerKey = controller_key
        cdrom.key = -1
        cdrom.connectable = connectable
        cdrom.backing = backing
        return cdrom

 
    def main(self):

        return_dict = {}
        message = []

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            content = service_instance.RetrieveContent()

            # finding the vm by name using get_obj, no datacenter specified
            vm = self.get_obj(content, [vim.VirtualMachine], self.vm_name)

            if vm:
                message.append("Found vm: " + self.vm_name)
            else:
                raise ERROR_exception("Can't find specified vm")


            
           # if self.datacenter:
           #     dc = get_dc(si, .datacenter)
           # else:
           #     dc = si.content.rootFolder.childEntity[0]


            controller = self.find_free_ide_controller(vm)
            #print controller
            if controller is None:
                raise ERROR_exception('Failed to find a free slot on the IDE controller')

            cdrom = None # want to add a new one
            
            # if we want the cdrom to be linked to a physical device
            if self.physical:
                cdrom_lun = get_physical_cdrom(vm.runtime.host)
                if cdrom_lun is not None:
                    backing = vim.vm.device.VirtualCdrom.AtapiBackingInfo()
                    backing.deviceName = cdrom_lun.deviceName
                    deviceSpec = vim.vm.device.VirtualDeviceSpec()
                    deviceSpec.device = self.new_cdrom_spec(controller.key, backing)
                    deviceSpec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
                    configSpec = vim.vm.ConfigSpec(deviceChange=[deviceSpec])
                    WaitForTask(vm.Reconfigure(configSpec))

                    cdroms = find_device(vm, vim.vm.device.VirtualCdrom)
                    cdrom = filter(lambda x: type(x.backing) == type(backing) and
                                   x.backing.deviceName == cdrom_lun.deviceName,
                                   cdroms)[0]
                else:
                    message.append('Skipping physical CD-Rom test as no device present.')
                    if not self.json:
                        print message[-1]


            # if we want to connect the cdrom to a iso image
            if self.iso is not None:
                op = vim.vm.device.VirtualDeviceSpec.Operation
                deviceSpec = vim.vm.device.VirtualDeviceSpec()
                if cdrom is None:  # add a cdrom
                    backing = vim.vm.device.VirtualCdrom.IsoBackingInfo(fileName=self.iso)
                    cdrom = self.new_cdrom_spec(controller.key, backing)
                    deviceSpec.operation = op.add
                else:  # edit an existing cdrom
                    backing = vim.vm.device.VirtualCdrom.IsoBackingInfo(fileName=self.iso)
                    cdrom.backing = backing
                    deviceSpec.operation = op.edit
                deviceSpec.device = cdrom
                configSpec = vim.vm.ConfigSpec(deviceChange=[deviceSpec])
                task = vm.Reconfigure(configSpec)
                tasks.wait_for_tasks(service_instance, [task])

                cdroms = self.find_device(vm, vim.vm.device.VirtualCdrom)
                cdrom = filter(lambda x: type(x.backing) == type(backing) and
                               x.backing.fileName == self.iso, cdroms)[0]
                message.append("added cdrom: " + cdrom.deviceInfo.label)

            else:
                message.append('Skipping ISO test as no iso provided.')
                if not self.json:
                    print message[-1]

            #if cdrom is not None:  # Remove it
            #    deviceSpec = vim.vm.device.VirtualDeviceSpec()
            #    deviceSpec.device = cdrom
            #    deviceSpec.operation = op.remove
            #    configSpec = vim.vm.ConfigSpec(deviceChange=[deviceSpec])
            #    task = vm.Reconfigure(configSpec)
            #    tasks.wait_for_tasks(service_instance, [task])


        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
        
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True



#
# vmware_datastore_upload
#

class vmware_datastore_upload(base.vmware_base):
    description = "upload file to datastore"

    def __init__(self, host, user, password, json, local_file, datastore, remote_file):
        super(vmware_datastore_upload, self).__init__("vmware_datastore_upload", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.json = json
        self.local_file = local_file
        self.datastore = datastore
        self.remote_file = remote_file

    def main(self):
        message = []
        return_dict = {}

        try:
            # File validation
            if not os.path.isfile(self.local_file):
                raise ERROR_exception("The provided local file doesn't exist")
            else:
                pass
            
            # Connect to vcenter
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            if not service_instance:
                print("could not connect ot the host with given credentials")
                return False

            content = service_instance.RetrieveContent()
            session_manager = content.sessionManager

            # Get the list of all datacenters we have available to us
            datacenters_object_view = content.viewManager.CreateContainerView(
                content.rootFolder,
                [vim.Datacenter],
                True)

            # Find the datastore and datacenter we are using
            datacenter = None
            datastore = None
            for dc in datacenters_object_view.view:
                datastores_object_view = content.viewManager.CreateContainerView(
                    dc,
                    [vim.Datastore],
                    True)
                for ds in datastores_object_view.view:
                    if ds.info.name == self.datastore:
                        datacenter = dc
                        datastore = ds

            if not datacenter or not datastore:
                raise ERROR_exception("Could not find the datastore specified")

            # Clean up the views now that we have what we need
            datastores_object_view.Destroy()
            datacenters_object_view.Destroy()

            # Build the url to put the file - https://hostname:port/resource?params
            if not self.remote_file.startswith("/"):
                remote_file = "/" + self.remote_file
            else:
                remote_file = self.remote_file
            resource = "/folder" + remote_file
            params = {"dsName": datastore.info.name,
                      "dcPath": datacenter.name}
            http_url = "https://" + self.host + ":443" + resource

            # Get the cookie built from the current session
            client_cookie = service_instance._stub.cookie
            # Break apart the cookie into it's component parts - This is more than
            # is needed, but a good example of how to break apart the cookie
            # anyways. The verbosity makes it clear what is happening.
            cookie_name = client_cookie.split("=", 1)[0]
            cookie_value = client_cookie.split("=", 1)[1].split(";", 1)[0]
            cookie_path = client_cookie.split("=", 1)[1].split(";", 1)[1].split(
                ";", 1)[0].lstrip()
            cookie_text = " " + cookie_value + "; $" + cookie_path
            # Make a cookie
            cookie = dict()
            cookie[cookie_name] = cookie_text

            # Get the request headers set up
            headers = {'Content-Type': 'application/octet-stream'}

            # Get the file to upload ready, extra protection by using with against
            # leaving open threads
            message.append("uploading " + self.local_file + " to " + self.datastore + " on " + self.host)

            with open(self.local_file, "rb") as f:
                # Connect and upload the file
                
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
 
                    request = requests.put(http_url,
                                           params=params,
                                           data=f,
                                           headers=headers,
                                           cookies=cookie,
                                           verify=False)
            
        except (ERROR_exception,vmodl.MethodFault) as e:

            if self.json:
                return_dict["success"] = "False"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["error"] = e.msg
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                print e.msg
                return False
            
        else:
            if self.json:
                return_dict["success"] = "True"
                meta_dict = meta.meta_header(host=self.host, user=self.user)
                return_dict["meta"] = meta_dict.main()
                return_dict["message"] = message
                return json.dumps(return_dict)
            else:
                return True


#
# vmware_create_snapshot module: create a snapshot for a vm
#

class vmware_create_snapshot(base.vmware_base):
    description = "This module creates a snapshot of a vm"

    def __init__(self, host, user, password, snap_name, snap_desc, **search):
        super(vmware_create_snapshot, self).__init__("vmware_create_snapshot", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.search = search
        self.snap_name = snap_name
        self.desc = snap_desc

    def get_obj(self, content, vimtype, name):
        """
        Return an object by name, if name is None the
        first found object is returned
        """
        obj = None
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True)
        for c in container.view:
            if name:
                if c.name == name:
                    obj = c
                    break
            else:
                obj = c
                break

        return obj


    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            return_dict = {}
            message = []

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "ip" in self.search:
                VM = service_instance.content.searchIndex.FindByIp(None, self.search["ip"], True)

            elif "domain_name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["domain_name"],
                                                                        True)
            elif "name" in self.search:
                content = service_instance.RetrieveContent()
                VM = self.get_obj(content, [vim.VirtualMachine], self.search["name"])

            else:
                raise ERROR_exception("No valid search criteria given")

            if VM is None:
                raise ERROR_exception("Unable to locate VirtualMachine.")

            message.append("Found: {0}".format(VM.name))
            message.append("Creating snapshot: " + self.snap_name)

            TASK = VM.CreateSnapshot_Task(name=self.snap_name,
                                          description=self.desc,
                                          memory=True,
                                          quiesce=False)

            tasks.wait_for_tasks(service_instance, [TASK])

            message.append("{0}".format(TASK.info.state))

        #   exception capture

        except (ERROR_exception,vmodl.MethodFault) as e:

            return_dict["success"] = "False"
            meta_dict = meta.meta_header(host=self.host, user=self.user)
            return_dict["error"] = e.msg
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)
    
        else:
            return_dict["success"] = "True"
            meta_dict = meta.meta_header(host=self.host, user=self.user)
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

