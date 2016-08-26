import vmware_module

#test_poweron = vmware_module.vmware_get_vms("10.2.1.50", "hgu@SS.local", "hguSS!234", True)

#test_poweron = vmware_module.vmware_delete_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, uuid="420512dc-feef-2f72-37b1-27b7afef9bce")

test_poweroff = vmware_module.vmware_poweroff_vm("10.2.1.50", "hgu@SS.local", "hguSS!234", True, ip="10.2.26.142")

print(test_poweroff.main())


