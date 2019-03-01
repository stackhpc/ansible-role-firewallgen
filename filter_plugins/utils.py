from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError, AnsibleFilterError
from operator import itemgetter

def sort_multi(data, *args):
    ''' sort list using multiple attributes
    '''
    return sorted(data, key = itemgetter(*args))

def keyvalue_dict(data):
    result = {}
    for item in data:
        if item["key"]:
            result[item["key"]] = item["value"]
    return result

def single_quote(string):
    return "'" + string + "'"

def socket_to_rule(socket):
    hint = ''
    if socket['processes'][0]['docker_hint']:
        hint = " in docker container '{}'".format(
            socket['processes'][0]['docker_hint']
        )
    if "haproxy_hint" in socket['processes'][0]:
        service = socket['processes'][0]["haproxy_hint"]
        hint = " for {}".format(service)
    comment = "hint: used by '{process}'{hint}".format(
        process=socket['processes'][0]['name'],
        hint=hint
        )
    return {
        'interface': socket["interface"],
        'port': socket["port"],
        'destination': socket["ip"],
        'comment': comment,
        'proto': socket["proto"],
    }


def firewallgen_rules(sockets):
    return [ socket_to_rule(socket) for socket in sockets]

class FilterModule(object):
    ''' Query filter '''

    def filters(self):
        return {
            'sort_multi': sort_multi,
            'keyvalue_dict': keyvalue_dict,
            'single_quote': single_quote,
            'firewallgen_rules': firewallgen_rules
        }
