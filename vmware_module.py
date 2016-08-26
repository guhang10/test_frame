# This file contains all the test realted to vmware application
# It will follow the same convention, all modules must inherit from vmware_base and coantains a main function

import base
import atexit
import ssl
import json
import meta

from vm_tools import tasks
from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim

#
# Custom exception
#
class ERROR_exception(Exception):
        def __init__(self, message):
            self.message = message

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

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

        except Exception as e:
            print e
            return_dict["success"] = "false"
            meta_dict = meta.meta_header(self.host, self.user, "oops", ERROR=error.msg)
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)

        return_dict["success"] = "true"
        meta_dict = meta.meta_header(self.host, self.user, "ok")
        return_dict["meta"] = meta_dict.main()
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

            return_dict = {}
            return_dict["result"] = []

            for child in children:

                if not self.json:
                    self.print_vm_info(child)

                else:
                    return_dict["result"].append(self.construct_dict(child))


        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)
            
            if self.json:
                return_dict["success"] = "false"
                meta_dict = meta.meta_header(self.host, self.user, "oops", ERROR=error.msg)
                return_dict["meta"] = meta_dict.main() 
                return json.dumps(return_dict)
            else:
                return False
        
        if self.json:
            return_dict["success"] = "true"
            meta_dict = meta.meta_header(self.host, self.user, "ok")
            return_dict["meta"] = meta_dict.main()
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

            elif "name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["name"],
                                                                        True)
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
         
        except vmodl.MethodFault as error:

            raise ERROR_exception(error.msg)

        except ERROR_exception as e:

            if self.json:
                return_dict["success"] = "false"
                meta_dict = meta.meta_header(self.host, self.user, "oops", ERROR=e.message)
                return_dict["meta"] = meta_dict.main()
                return json.dumps(return_dict)
            else:
                print e.message
                return False
            
        if self.json:
            return_dict["success"] = "true"
            meta_dict = meta.meta_header(self.host, self.user, message)
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)
        else:
            return True
        
   
#
# vmware_poweron_vm module: this module will not ipaddress as filter, off machines don't have ip field
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

    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["name"],
                                                                        True)
            else:
                print "No valid search criteria given"
                return False

            if VM is None:
                print "Unable to locate VirtualMachine."
                return False

            return_dict = {}
            message = []

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
         

        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)

            if self.json:
                return_dict["success"] = "false"
                meta_dict = meta.meta_header(self.host, self.user, message, ERROR=error.msg)
                return_dict["meta"] = meta_dict.main()
                return json.dumps(return_dict)
            else:
                return False

        if self.json:
            return_dict["success"] = "true"
            meta_dict = meta.meta_header(self.host, self.user, message)
            return_dict["meta"] = meta_dict.main()
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

    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "ip" in self.search:
                VM = service_instance.content.searchIndex.FindByIp(None, self.search["ip"], True)

            elif "name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["name"],
                                                                        True)
            else:
                print "No valid search criteria given"
                return False

            if VM is None:
                print "Unable to locate VirtualMachine."
                return False
            
            return_dict = {}
            message = []

            message.append("Found: {0}".format(VM.name))
            message.append("The current powerState is: {0}".format(VM.runtime.powerState))

            if not self.json:
                for i in message[0:2]: print i

            if VM.runtime.powerState != "poweredOff":
                message.append("Attempting to power off {0}".format(VM.name))
                print message[3]

                TASK = VM.PowerOffVM_Task()
                tasks.wait_for_tasks(service_instance, [TASK])
            
                message.append("{0}".format(TASK.info.state))
                message.append("The current powerState is: {0}".format(VM.runtime.powerState))

                if not self.json:
                    for i in message[3:5]: print i

            message.append("Attempting to delete {0}".format(VM.name))
            print message[-1]
            
            TASK = VM.Destroy_Task()
            tasks.wait_for_tasks(service_instance, [TASK])
            
            message.append("{0}".format(TASK.info.state))
            if not self.json:
                print message[-1]
            
        
        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)

            if self.json:
                return_dict["success"] = "false"
                meta_dict = meta.meta_header(self.host, self.user, message, ERROR=error.msg)
                return_dict["meta"] = meta_dict.main()
                return json.dumps(return_dict)
            else:
                return False

        if self.json:
            return_dict["success"] = "true"
            meta_dict = meta.meta_header(self.host, self.user, message)
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)
        else:
            return True


#
# vmware_reset_vm module: this module reset a vm (hard reset)
#

class vmware_reset_vm(base.vmware_base):
    description = "hard reset a vm"

    def __init__(self, host, user, password, **search):
        super(vmware_reset_vm, self).__init__("vmware_reset_vm", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.search = search

    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "ip" in self.search:
                VM = service_instance.content.searchIndex.FindByIp(None, self.search["ip"], True)

            elif "name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["name"],
                                                                        True)
            else:
                print "No valid search criteria given"
                return False

            if VM is None:
                print "Unable to locate VirtualMachine."
                return False

            print("Found: {0}".format(VM.name))
            print("The current powerState is: {0}".format(VM.runtime.powerState))
            print("Attempting to reset {0}".format(VM.name))
            TASK = VM.ResetVM_Task()
            tasks.wait_for_tasks(service_instance, [TASK])
            print("{0}".format(TASK.info.state))

        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)
            return False
        
        print "complete !"
        return True



#
# vmware_soft_reboot_vm module: this module send target vm a  reboot signal(no gurantee for a reboot though)
#

class vmware_soft_reboot_vm(base.vmware_base):
    description = "send vm a soft reboot signal"

    def __init__(self, host, user, password, **search):
        super(vmware_soft_reboot_vm, self).__init__("vmware_soft_reboot_vm", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password
        self.search = search

    def main(self):

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            if "uuid" in self.search:
                VM = service_instance.content.searchIndex.FindByUuid(None, self.search["uuid"],
                                                                     True, False)
            elif "ip" in self.search:
                VM = service_instance.content.searchIndex.FindByIp(None, self.search["ip"], True)

            elif "name" in self.search:
                VM = service_instance.content.searchIndex.FindByDnsName(None, self.search["name"],
                                                                        True)
            else:
                print "No valid search criteria given"
                return False

            if VM is None:
                print "Unable to locate VirtualMachine."
                return False

            print("Found: {0}".format(VM.name))
            print("The current powerState is: {0}".format(VM.runtime.powerState))
            print("Attempting to reset {0}".format(VM.name))
            TASK = VM.RebootGuest()

        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)
            return False
        
        print "complete !"
        return True


#
#  wmare_list_datastore_info module: still haven't decide whether I want json output yet...mmm....
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

        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)

            atexit.register(connect.Disconnect, service_instance)

            if not service_instance:
                print("could not connect ot the host with given credentials")
                return False

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

            if self.json:
                return json.dumps(datastores)

        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)
            return False

        return True
















