#
# This file contains modules that will be use as bases of tasks, modules perform the key functions of the test
# every module will contain a main function that execute the logic 
# task.
# Modules will be result oriented, it will return both the result(fail or pass) and a meta field (a report that contains the returned value or text
#

import base
import getpass
import paramiko
import socket
import errno
import sys
import time
import os
import meta
import json
import subprocess
import signal

#
# Custom exception
#

class ERROR_exception(Exception):
        def __init__(self, msg):
            self.msg = msg


#
# ping_test module: ping an ip until it's up or the time runs out
#
class ping_test(base.local_base):
    description = 'ping a box until a box come up or the maximum time limit is reached'

    def __init__(self, ip, max_span):
        super(ping_test, self).__init__("ping test", "n/a")
        self.ip = ip
        self.max_span = str(max_span)

    def main(self):
        message = []
        return_dict = {}
        devnull = open(os.devnull, 'w')

        try:
            result = subprocess.call(["ping", "-c", "2", "-w", self.max_span, self.ip], stdout=devnull, stderr=devnull)
            
            if not result:
                message.append("ping response received")
            else:
                raise ERROR_exception("ping response is not received within the time limit")

        except ERROR_exception as e:

            return_dict["success"] = "False"
            meta_dict = meta.meta_header()
            return_dict["error"] = e.msg
            return_dict["meta"] = meta_dict.main()
            return_dict["message"] = message
            return json.dumps(return_dict)

        else:
            return_dict["success"] = "True"
            meta_dict = meta.meta_header()
            return_dict["message"] = message
            return_dict["meta"] = meta_dict.main()
            return json.dumps(return_dict)






