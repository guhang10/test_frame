#!/usr/local/bin/python2.7

import json
import os
import subprocess

command_list = [{"command": "search", "table": "port", "fields": ["name", "device.name", "IF-MIB.ifOperStatus"]}, 
        { "command": "search", "table": "framerelay", "fields": ["name", "device.name", "FRAME-RELAY-DTE-MIB.frCircuitState"] },
        { "command": "search", "table": "temperature_cisco", "fields": ["name", "device.name", "CISCO-ENVMON-MIB.ciscoEnvMonTemperatureState"]},
        { "command": "search", "table": "ups_generic", "fields": ["name", "device.name", "UPS-MIB.upsOutputSource"]},
        { "command": "search", "table": "ups_generic", "fields": ["name", "device.name", "UPS-MIB.upsBatteryStatus"]},
        { "command": "search", "table": "ups_apc", "fields": ["name", "device.name", "PowerNet-MIB.upsAdvBatteryReplaceIndicator"] }]

max_len = [1, 5, 5, 5, 5, 5]       # This is the max number of devices added to the group for each oid

def group_create(group_name, object_str):
    group_info = subprocess.check_output (["base-ega", "add", "group", group_name]).rstrip()
    subprocess.call (["base-ega", "access", "add", "group", group_name, object_str])
    return group_info

for i, (command, max_len) in enumerate(zip(command_list, max_len)):
    field = command["fields"][2]
    oid = field.split(".")[1]
    device_set = set()
    index_list = []
    object_list = []
    # Set a quantity that can be desplayed on one page, easier to check
    quantity = 10
    cfg_search = subprocess.check_output(["nim-cfg","get", "*:*:" + oid + ":*"])

    for item in cfg_search.split("\n"):
        if item:
            iden = item.split(" ")[0].split(":")
            device_set.add(iden[0])
            index_list.append(iden[-1])

    if i == 0:
        device_list = list(device_set)[49:50+(max_len)]
    else:
        device_list = list(device_set)[:max_len]


    for device_name in device_list:
        object_list.append("device")
        object_list.append(device_name)
    
    if object_list:
        group_name = command["table"] + "%" + command["fields"][2]
        group_info = group_create(group_name, " ".join(object_list))

    group_id = int(group_info.split(" ")[0].strip("\'"))
    command["filters"] = [{"field":"groupid", "op": "=", "val": group_id}]
    command["limit"] = 0
    
    api_result = json.loads(subprocess.check_output (["nim-api", json.dumps(command)]))["result"]

    print "\n" + field + "\n"
    print device_list
    print group_id
    
    for result in api_result:
        print result["device.name"] + "  " + result["name"] + "  " + str(result[field])



