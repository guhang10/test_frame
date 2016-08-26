import json
import time
import calendar

class meta_header(object):
    description = "construct meta for json return"

    def __init__(self, host, user, message, **kwargs):
        self.host = host
        self.user = user
        self.message = message

        if "result_total" in kwargs:
            self.result_total = kwargs["result_total"]

        print kwargs

        if "ERROR" in kwargs:
            self.error = kwargs["ERROR"]

    def main(self):
        meta = {}
        meta["host"] = self.host
        meta["user"] = self.user
        meta["message"] = self.message
        meta["epoch"] = calendar.timegm(time.gmtime())
        meta["time"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
        meta["tz"] = time.timezone / -(60*60)

        try:
            meta["error"] = self.error

        except AttributeError:
            pass

        try:
            meta["error"] = self.result_total

        except AttributeError:
            pass

        return meta





