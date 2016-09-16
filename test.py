#################################################################################################################
# command template for testing vmware modules
#################################################################################################################
import vmware_module
import statseeker_module

auto_iso_gen = statseeker_module.auto_iso_gen("em0", "10.2.26.155", "255.255.255.0","10.2.26.254", "qa-vm-auto@statseeker.com", "10.1.5.2", "$6$4thfn1RHRHr6mrYA$mz0JES4qk6mxIDx9cUWmttDcnIhN.Svv7/4M3D6OPgA8pNGeEDTKmqoJf6bGepHaMA8lyLnIvlioLf3AyWpRq/", "/home/hang/Desktop/build/statseeker_5.0.0_install_64bit.iso",  "auto_test.iso")
test_upload = vmware_module.vmware_datastore_upload("10.2.1.50", "hgu@SS.local", "hguSS!234", True, "auto_test.iso", "datastore2-qa", "auto_install.iso")
test_get = vmware_module.vmware_get_vms("10.2.1.50", "hgu@SS.local", "hguSS!234", False)
test_poweron = vmware_module.vmware_poweron_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, name="qa-vm-auto")
#test_poweroff = vmware_module.vmware_poweroff_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, name="qa-vm-create_test_1")
test_delete = vmware_module.vmware_delete_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, name="qa-vm-auto")
#test_reset = vmware_module.vmware_reset_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, name="qa-vm-create_test_1")
#test_reboot = vmware_module.vmware_soft_reboot_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, name="qa-vm-create_test_1")
#list_datastore = vmware_module.vmware_list_datastore_info("10.2.1.50", "hgu@SS.local", "hguSS!234", True)
#clone_vm = vmware_module.vmware_clone_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, "qa-vm-test15x", "qa-vm-test142", resource_pool="QA-RP1", power_on=False)
create_vm = vmware_module.vmware_create_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, "qa-vm-auto", "datastore2-qa", memoryMB=4096, numCPUs=2)
add_disk = vmware_module.vmware_add_disk("10.2.1.50", "hgu@SS.local", "hguSS!234", True, "qa-vm-auto", "Thick", 400)
add_test_nic = vmware_module.vmware_add_nic("10.2.1.50", "hgu@SS.local", "hguSS!234", True, "qa-vm-auto", "TEST_QA")
#add_ha_nic = vmware_module.vmware_add_nic("10.2.1.50", "hgu@SS.local", "hguSS!234", True, "qa-vm-test146", "HA")
add_cdrom = vmware_module.vmware_add_cdrom("10.2.1.50", "hgu@SS.local", "hguSS!234", True, "qa-vm-auto", "cdrom_test", iso="[datastore2-qa] auto_install.iso")

#print(test_poweroff.main())
#print (test_get.main())
#print (test_reboot.main())
#print (list_datastore.main())
#print (clone_vm.main())
#print (test_reset.main())
#print (test_poweroff.main())

#print (test_delete.main())
print(auto_iso_gen.main())
print(test_upload.main())
print (create_vm.main())
print (add_disk.main())
print (add_test_nic.main())
print (add_cdrom.main())
print (test_poweron.main())

#################################################################################################################



