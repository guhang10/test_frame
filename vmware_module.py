# This file contains all the test realted to vmware application
# It will follow the same convention, all modules must inherit from vmware_base and coantains a main function

import base
import atexit
import ssl

from pyVim import connect
from pyVmomi import vmodl
from pyVmomi import vim

class vmware_connect_test(base.vmware_base):

    def __init__(self, host, user, password):
        super(vmware_connect_test, self).__init__("vmware_conncet_test", "6")
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


vmware_connect_test_1 = vmware_connect_test("10.2.1.50", "hgu@SS.local", "hguSS!234")
vmware_connect_test_1.main()



