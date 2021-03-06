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
import urllib2
import httplib
import hashlib
import traceback
from pprint import pprint

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

        except error_exception as e:
            return output_builder(message, e.msg, 1)
        except Exception:
            return output_builder(message, 'generic exception: ' + traceback.format_exc(), 1)
        else:
            return output_builder(message,'', 0)


#
# file_download: this module is intended to retrieve a single file using url
#

class file_download(base.local_base):
    description = 'retrieve a single file using url'

    def __init__(self, url, **kwargs):
        super(file_download, self).__init__("file_download", "n/a")
        self.url = url

        # define the save file name, with default
        if "file_name" in kwargs:
            self.file_name = kwargs["file_name"]
        else:
            self.file_name = url.split("/")[-1]

        # md5
        if "md5" in kwargs:
            self.md5 = kwargs["md5"]
            self.checksum = True
        else:
            self.checksum = False


    def main(self):
        message = []
        result = []
        return_dict = {}
        
        try:
            # retrieving file from url
            message.append("attempting to retrieve from " + self.url)
            hdr = {'User-Agent':'Mozilla/5.0'}
            req = urllib2.Request(self.url, headers=hdr)
            file_handle = urllib2.urlopen(req)

            message.append("success")

            # Open local file for writing
            message.append("saving to: " + self.file_name)
            with open (self.file_name, "wb") as local_file:
                local_file.write(file_handle.read())
            message.append("success")

            # md5 checking if specified (memory efficient, load file in chunks, in case of large file)
            if self.checksum:
                message.append("generating md5")
                hash_md5 = hashlib.md5()
                with open(self.file_name, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                message.append("success")
                result.append(hash_md5.hexdigest())
                
                # checking against the input md5sum
                message.append("checking md5")
                if hash_md5.hexdigest() == self.md5:
                    message.append("success")
                else:
                    raise ERROR_exception("md5 mismatch")

        # Error handeling
        except ERROR_exception as e:
            return output_builder(message, e.msg, 1)
        except urllib2.HTTPError, e:
            return output_builder(message, 'HTTPError = ' + str(e.code), 1)
        except urllib2.URLError, e:
            return output_builder(message, 'URLError = ' + str(e.reason), 1)
        except httplib.HTTPException, e:
            return output_builder(message, 'HTTPException', 1)
        except Exception:
            return output_builder(message, 'generic exception: ' + traceback.format_exc(), 1)
        else:
            return output_builder(message, '', 0, result=result)








