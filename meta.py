import json
import time
import calendar

class meta_header(object):
    description = "construct meta for json return"

    def __init__(self, **kwargs):

        if "host" in kwargs:
            self.host = kwargs["host"]

        if "user" in kwargs:
            self.user = kwargs["user"]

        if "result_total" in kwargs:
            self.result_total = kwargs["result_total"]

        if "ERROR" in kwargs:
            self.error = kwargs["ERROR"]

    def main(self):
        meta = {}
        meta["epoch"] = calendar.timegm(time.gmtime())
        meta["time"] = time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime())
        meta["tz"] = time.timezone / -(60*60)

        try:
            meta["host"] = self.host
            meta["user"] = self.user
            meta["error"] = self.error
            meta["result_total"] = self.result_total

        except AttributeError:
            pass

        return meta





