# Copyright (c) 2017 Pani Networks Inc
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import simplejson
import socket

from neutron_lib import constants

from oslo_log import log

from six.moves.urllib.parse import urljoin
from six.moves.urllib.request import HTTPHandler
from six.moves.urllib.request import Request
from six.moves.urllib.request import build_opener

from networking_romana.driver import exceptions

LOG = log.getLogger(__name__)


def find_host_info(romana_url, name):
    """ Find Romana host information for a given name."""
    host_lookup = {'name': name}
    hosts_url = urljoin(romana_url, "/hosts")
    hosts_resp = http_call("GET", hosts_url)
    hosts = hosts_resp.get('hosts')
    for host in hosts:
        if host.get('name') == name:
            return host
    return dict(name='', ip='')


def http_call(method, url, data=None):
    """Utility method for making HTTP requests."""
    LOG.debug("http_call(): Calling %s %s" % (method, url))
    opener = build_opener(HTTPHandler)
    if data:
        data = simplejson.dumps(data)
        LOG.debug("http_call(): With body: %s" % data)
    request = Request(url, data)
    request.add_header('Accept', 'application/json')
    if data:
        request.add_header('Content-Type', 'application/json')
    request.get_method = lambda: method
    resp = opener.open(request)
    if resp.getcode() >= 400:
        raise exceptions.RomanaException(
            "Error in method(%s) url(%s) with payload(%s): %s" %
            (method, url, data, resp))
    body = resp.read()
    if body != "":
        LOG.debug("body: %s" % body)
        data = simplejson.loads(body)
        return data
    return ""


def romana_allocate_ip_address(romana_url, name, tenant, segment, host=None):
    """Call Romana Daemon Service to allocate IP Address to the VM."""
    if host is None or host == constants.ATTR_NOT_SPECIFIED:
        host = socket.gethostname()
    iprequest = {
        'name': name,
        'host': host,
        'tenant': tenant,
        'segment': segment
    }
    LOG.debug("romana_allocate_ip_address, request(%s)", iprequest)
    try:
        resp = http_call("POST", romana_url + "/address", iprequest)
    except Exception as e:
        raise exceptions.RomanaException(
            "Error allocating IP for VM(%s) on Host(%s) for Tenant(%s) and Segment(%s): %s" %
            (name, host, tenant, segment, e)
        )
    return resp


def romana_deallocate_ip_address(romana_url, ipaddress):
    """Call Romana Daemon Service to deallocate IP Address."""
    address_request = {'addressName': ipaddress}
    LOG.debug("romana_deallocate_ip_address, request(%s)", address_request)
    try:
        r_url = romana_url + "/address?addressName=" + ipaddress
        resp = http_call("DELETE", r_url)
    except Exception as e:
        raise exceptions.RomanaException("Error deallocating IP(%s): %s" % (ipaddress, e))
    return resp


def romana_update_port(romana_url, host, interface, mac, ip):
    """Call Romana Agent to update the Port for the VM."""
    agent_host_info = find_host_info(romana_url, host)
    agent_host_ip = agent_host_info.get("ip")
    if agent_host_ip == "":
        raise exceptions.RomanaException(
            "couldn't find Host IP and Port on which agent is running, host(%s) info(%s)" %
            (host, agent_host_info))
    agent_host_port = agent_host_info.get("agent_port")
    romana_url = 'http://{0}:{1}/vm'.format(agent_host_ip, agent_host_port)
    data = {'interface': interface, 'mac': mac, 'ip': ip}
    LOG.debug("romana_update_port, url(%s), data(%s)", romana_url, data)
    try:
        resp = http_call('POST', romana_url, data)
    except exceptions.RomanaException:
        raise
    except Exception as e:
        raise exceptions.RomanaAgentConnectionException(romana_url, data, e)
    return resp


def romana_delete_port(romana_url, host, mac):
    """Call Romana Agent to delete Port."""
    agent_host_info = find_host_info(romana_url, host)
    agent_host_ip = agent_host_info.get("ip")
    if agent_host_ip == "":
        raise exceptions.RomanaException(
            "couldn't find Host IP and Port on which agent is running, host(%s) info(%s)" %
            (host, agent_host_info))
    agent_host_port = agent_host_info.get("agent_port")
    agent_url = "http://%s:%s/vm" % (agent_host_ip, agent_host_port)
    r_url = agent_url + "/" + mac
    LOG.debug("romana_delete_port, url(%s), data(%s)", romana_url, mac)
    try:
        resp = http_call("DELETE", r_url)
    except exceptions.RomanaException:
        raise
    except Exception as e:
        data = 'host(%s) and mac(%s)' % (host, mac)
        raise exceptions.RomanaAgentConnectionException(r_url, data, e)
    return resp
