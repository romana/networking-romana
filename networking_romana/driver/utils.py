import simplejson

from oslo_log import log

from six.moves.urllib.parse import urlparse, urljoin
from six.moves.urllib.request import HTTPHandler, Request, build_opener

from networking_romana.driver import exceptions

LOG = log.getLogger(__name__)

def find_romana_service_url(romana_url, service_name):
    """
    Finds URL to Romana service based on name
    
    """
    root_resp = http_call("GET", romana_url)
    LOG.debug("find_romana_service_url(): Root responds: %s" % root_resp)
    services = root_resp.get('services')
    service_url = None
    for service in services:
        if service['name'] == service_name:
            links = service['links']
            for link in links:
                if link['rel'] == 'service':
                    return link['href']
    raise exceptions.RomanaException("URL for service %s not found." % service_name)

def find_host_info(romana_url, name):
    """
    Find Romana host information for a given name.

    """
    host_lookup = { 'name' : name }
    romana_host_id =  find_romana_id(romana_url, 'host', host_lookup)
    topo_url = find_romana_service_url(romana_url, "topology")
    host_url = urljoin(topo_url, "/hosts/%s" % romana_host_id)
    resp = http_call("GET", host_url)
    return resp

def find_romana_id(romana_url, entity_type, lookup_dict):
    """
    Finds the Romana ID of the specified Romana entity (e.g., segment,
    tenant) based on value of a provided field. Exactly one result is
    expected, otherwise an Exception is raised.

    :param entity_type: Romana entity type ('host', 'segment' or 'tenant')
    :param lookup_dict: dictionary whose fields are names and whose values are field
    values
    
    """
    if entity_type == 'tenant' or entity_type == 'segment':
        service_name = 'tenant'
    elif entity_type == 'host':
        service_name= 'topology'
    else:
        raise exceptions.RomanaException("Unknown entity %s" % entity_type)
    service_url = find_romana_service_url(romana_url,
                                                service_name)
    qs = "&".join([     "%s=%s" % (k, v) for k, v in lookup_dict.iteritems()])
    find_url = urljoin(service_url,
                       "findExactlyOne/%ss?%s" %
                       (entity_type, qs))
    resp = http_call("GET", find_url)
    if "id" in resp:
        return resp["id"]
    else:
        msg = "Cannot find %s in response %s." % (id_field, resp)
        raise exceptions.RomanaException(msg)


def find_agent_port(romana_url):
    """
    Retrieves agent port from configuration via root service.

    """

    root_resp = http_call("GET", romana_url)
    LOG.debug("find_romana_service_url(): Root responds: %s" % root_resp)
    try:
        links = root_resp['links']
        for link in links:
            if link['rel'] == 'agent-config':
                href = link['href']
                agent_config_url = urljoin(romana_url, href)
                agent_config = http_call("GET", agent_config_url)
                return agent_config['common']['api']['port']
    except exceptions.RomanaException:
        raise
    except Exception, e:
        raise exceptions.RomanaException("Error getting agent port: %s" % e)
    raise exceptions.RomanaException("Error getting agent port.")
    

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
        raise exceptions.RomanaException("Error in %s %s with payload %s: %s", method, url, data, resp)
    body = resp.read()
    data = simplejson.loads(body)
    return data
