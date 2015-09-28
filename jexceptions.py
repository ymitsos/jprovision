# -*- coding: utf-8 -*-
'''
A python script that uses junos-eznc and consequently ncclient and
NETCONF to push massively configuration, read from a file, to a number
of Juniper equipment. Results are tracked in log file.

'''
# Authors: {ymitsos,mmamalis}_at_noc_dot_grnet_dot_gr


class jException(Exception):

    def __init__(self, error, host=None):
        self.error = error
        self.host = error.host if hasattr (error, 'host') else host
        self.errs = error.errs if hasattr (error, 'errs') else None

    def __str__(self):
        self.message = str('Received a ' + type(self.error).__name__  + ' exception while trying to connect to ' + self.host)
        return repr(self.message)

    pass
