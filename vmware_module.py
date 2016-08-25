# This file contains all the test realted to vmware application
# It will follow the same convention, all modules must inherit from vmware_base and coantains a main function

import base
import atexit
import ssl
import json

from vm_tools import tasks
from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim


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
        try:
            service_instance = connect.SmartConnect(host=self.host ,user=self.user,
                    pwd=self.password, port=443, sslContext=self.context)
            print service_instance
            return True

        except Exception as e:
            print e
            return False


#
# vmware_get_vms module
#

class vmware_get_vms(base.vmware_base):
    description = "show all vms on a vmware host"

    def __init__(self, host, user, password):
        super(vmware_get_vms, self).__init__("vmware_get_vms", "6.0.0")
        self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        self.context.verify_mode = ssl.CERT_NONE
        self.host = host
        self.user = user
        self.password = password

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
            for child in children:
                self.print_vm_info(child)

        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)
            return False

        return True


#
# vmware_poweroff_vm module
#

class vmware_poweroff_vm(base.vmware_base):
    description = "power off a vm"

    def __init__(self, host, user, password, **search):
        super(vmware_poweroff_vm, self).__init__("vmware_poweroff_vm", "6.0.0")
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
            print("Attempting to power off {0}".format(VM.name))
            TASK = VM.PowerOffVM_Task()
            tasks.wait_for_tasks(service_instance, [TASK])
            print("{0}".format(TASK.info.state))
            print("The current powerState is: {0}".format(VM.runtime.powerState))
            
        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)
            return False
        
        print "complete !"
        return True



#
# vmware_poweron_vm module: this module will not ipaddress as filter, off machines don't have ip field
#

class vmware_poweron_vm(base.vmware_base):
    description = "power on a vm"

    def __init__(self, host, user, password, **search):
        super(vmware_poweron_vm, self).__init__("vmware_poweron_vm", "6.0.0")
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
            print("Attempting to power on {0}".format(VM.name))
            TASK = VM.PowerOnVM_Task()
            tasks.wait_for_tasks(service_instance, [TASK])
            print("{0}".format(TASK.info.state))
            print("The current powerState is: {0}".format(VM.runtime.powerState))
            
        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)
            return False
        
        print "complete !"
        return True



#
# vmware_delete_vm module
#
  
class vmware_delete_vm(base.vmware_base):
    description = "delete a vm"

    def __init__(self, host, user, password, **search):
        super(vmware_delete_vm, self).__init__("vmware_delete_vm", "6.0.0")
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
            print("Attempting to power off {0}".format(VM.name))
            TASK = VM.PowerOffVM_Task()
            tasks.wait_for_tasks(service_instance, [TASK])
            print("{0}".format(TASK.info.state))
            print("Destroying VM from vSphere.")
            TASK = VM.Destroy_Task()
            tasks.wait_for_tasks(service_instance, [TASK])
            print("{0}".format(TASK.info.state))

        except vmodl.MethodFault as error:
            print("Caught vmodl fault : " + error.msg)
            return False
        
        print "complete !"
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











