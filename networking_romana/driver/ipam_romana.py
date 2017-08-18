# Copyright (c) 2016 Pani Networks Inc
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


import MySQLdb
import netaddr

from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils

from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import utils as common_utils
from neutron_lib import exceptions
from neutron.ipam import driver as ipam_base
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc
from neutron import manager

from six.moves.urllib.parse import urljoin
from six.moves.urllib.parse import urlparse

from networking_romana.driver import exceptions
from networking_romana.driver import utils

LOG = log.getLogger(__name__)

class RomanaDbSubnet(ipam_base.Subnet):
    """
    Manage IP addresses for Romana IPAM driver.

    """

    def __init__(self, internal_id, ctx, cidr=None,
                 gateway_ip=None, tenant_id=None,
                 subnet_id=None):
        """Initialize RomanaDbSubnet."""
        LOG.debug("RomanaDbSubnet.__init__()")
        self._cidr = cidr
        self._pools = []
        self._gateway_ip = gateway_ip
        self._tenant_id = tenant_id
        self._subnet_id = subnet_id
        self._context = ctx
        self._neutron_id = internal_id
        config = cfg.CONF.romana
        LOG.debug("RomanaDbSubnet.__init__()")
        if not config:
            raise ipam_exc.exceptions.InvalidConfigurationOption(
                {'opt_name': 'romana', 'opt_value': 'missing'})
        self.romana_url = config.url
        if not self.romana_url:
            raise ipam_exc.exceptions.InvalidConfigurationOption(
                {'opt_name': 'url', 'opt_value': 'missing'})
        LOG.debug("romana_url: %s" % self.romana_url)

    @classmethod
    def create_from_subnet_request(cls, subnet_request, ctx):
        """Create from a subnet request."""
        LOG.debug("RomanaDbSubnet.create_from_subnet_request()")
        ipam_subnet_id = uuidutils.generate_uuid()
        # Create subnet resource

        me = cls(ipam_subnet_id,
                 ctx,
                 cidr=subnet_request.subnet_cidr,
                 gateway_ip=subnet_request.gateway_ip,
                 tenant_id=subnet_request.tenant_id,
                 subnet_id=subnet_request.subnet_id)
        # Workaround for creating the 10/8 subnet
        if subnet_request.subnet_cidr.prefixlen > 8:
            me.allocate_segment()
        return me

    def allocate_segment(self):
        """This is a no-op in Romana model."""
        LOG.debug("RomanaDbSubnet.allocate_segment()")
        pass

    @classmethod
    def load(cls, neutron_subnet_id, ctx):
        """Load an IPAM subnet from the database given its neutron ID."""
        LOG.debug("RomanaDbSubnet.load()")
        neutron_subnet = cls._fetch_subnet(ctx, neutron_subnet_id)
        retval = cls(neutron_subnet_id,
                     ctx,
                     cidr=neutron_subnet['cidr'],
                     gateway_ip=neutron_subnet['gateway_ip'],
                     tenant_id=neutron_subnet['tenant_id'],
                     subnet_id=neutron_subnet_id)
        LOG.debug("IPAM subnet loaded: %s" % retval)
        return retval

    @classmethod
    def _fetch_subnet(cls, context, id):
        LOG.debug("RomanaDbSubnet._fetch_subnet()")
        plugin = manager.NeutronManager.get_plugin()
        return plugin._get_subnet(context, id)
    
    def allocate(self, address_request):
        """Allocate Address by calling Romana IPAM Agent."""

        LOG.debug("RomanaDbSubnet.allocate(%s)" % address_request)
        
        if isinstance(address_request, ipam_req.SpecificAddressRequest):
            msg = "Specific address allocation not supported by Romana."
            raise exceptions.RomanaException(msg)
        if isinstance(address_request, RomanaDhcpAddressRequest):
            host_name = address_request.host_name
            host_info = utils.find_host_info(self.romana_url, host_name)
            ip = host_info.get("ip")
            LOG.debug("Romana IPAM: To DHCP agent on host %s, assigning %s", host_name, ip)
            return ip
        ten_lookup = { 'external_id': address_request.tenant_id }
        romana_tenant_id = utils.find_romana_id(self.romana_url, 'tenant', ten_lookup)
        seg_lookup = { 'name' : address_request.segment_name, 
                       'tenant_id' : romana_tenant_id}
        romana_segment_id = utils.find_romana_id(self.romana_url, 'segment', seg_lookup)
        host_lookup = { 'name' : address_request.host_name }
        romana_host_id =  utils.find_romana_id(self.romana_url, 'host', host_lookup)
        ipam_service_url = utils.find_romana_service_url(self.romana_url, 
                                                         'ipam')
        url = urljoin(ipam_service_url, "/endpoints")
        endpoint = {'tenant_id'  : str(romana_tenant_id),
                    'segment_id' : str(romana_segment_id),
                    'host_id'    : str(romana_host_id)}
        try:
            resp = utils.http_call("POST", url, endpoint)
            ip = resp['ip']
        except Exception as e:
            LOG.error(e)
            raise exceptions.RomanaException("Error allocating: %s" % e)
        return ip

    def deallocate(self, address):
        """Deallocate an IP Address. Really, it's a noop, here we are not doing anything. 
        The logic lives in ML2 driver. 

        """
        pass

    def update_allocation_pools(self, pools):
        """Update Allocation Pools."""
        LOG.debug("RomanaDbSubnet.update_allocation_pools()")
        pass

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest."""
        LOG.debug("RomanaDbSubnet.get_details()")
        return ipam_req.SpecificSubnetRequest(
            self._tenant_id, self._neutron_id,
            self._cidr, self._gateway_ip, self._pools)


class RomanaDhcpAddressRequest(ipam_req.AnyAddressRequest):
        def __init__(self, host_name):
            super(ipam_req.AnyAddressRequest, self).__init__()
            self.host_name = host_name

class RomanaAnyAddressRequest(ipam_req.AnyAddressRequest):
    """Used to request any available address from the pool."""

    def __init__(self, host_name, tenant_id, segment_name):
        """Initialize RomanaAnyAddressRequest."""
        super(ipam_req.AnyAddressRequest, self).__init__()
        self.host_name = host_name
        self.tenant_id = tenant_id
        self.segment_name = segment_name

class RomanaAddressRequestFactory(ipam_req.AddressRequestFactory):
    """Builds address request using ip information."""

    _db_url = None
    _db_conn_dict = None

    @classmethod
    def get_request(cls, context, port, ip_dict):
        """Get a prepared Address Request.

        :param context: context
        :param port: port dict
        :param ip_dict: dict that can contain 'ip_address', 'mac' and
            'subnet_cidr' keys. Request to generate is selected depending on
             this ip_dict keys.
        :return: returns prepared AddressRequest (specific or any)
        """
        mac = port['mac_address']
        owner = port.get('device_owner')
        LOG.debug("AAA: \tTenant %s, is admin %s\n\tdevice owner: %s\n\t%s\n\t%s", context.tenant, context.is_admin, owner, port, ip_dict)
        if owner == constants.DEVICE_OWNER_DHCP:
            return RomanaDhcpAddressRequest(port.get('binding:host_id'))

        # Lazily instantiate DB connection info.
        if cls._db_url is None:
            cls._db_url = cfg.CONF.database.connection
            _parsed_db_url = urlparse(cls._db_url)
            cls._db_conn_dict = {'host': _parsed_db_url.hostname,
                                 'user': _parsed_db_url.username,
                                 'passwd': _parsed_db_url.password,
                                 'db': _parsed_db_url.path[1:]}
        LOG.debug("Connecting to %s" % cls._db_url)
        con = MySQLdb.connect(**cls._db_conn_dict)
        cur = con.cursor()

        # FIXIT! TODO(gg)
        # What a hack! This is being written by Neutron within a transaction,
        # so we have to do a dirty read. However, there is no other [good] way
        # of getting the information about the instance ID in Neutron-land
        # additional this point without patching Nova. The only fix I can
        # think of is actually a enhancement/blueprint to OpenStack for a more
        # flexible ways of creating requests. In other words, the decision
        # that only host ID and tenant ID (but not instance ID, for one)
        # should go into a request for an IP address lies right now with Nova,
        # but why can't it be made more pluggable/flexible, sort of akin
        # to https://review.openstack.org/#/c/192663/

        cur.execute("SET LOCAL TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")
        query = ("SELECT `key`, value FROM neutron.ports p JOIN "
                 "nova.instance_metadata im ON p.device_id = im.instance_uuid "
                 "WHERE mac_address = '%s' AND `key` = 'romanaSegment'" % mac)
        LOG.debug("DB Query: %s" % query)
        cur.execute(query)
        rows = [row for row in cur.fetchall()]
        cur.close()
        con.close()
        LOG.debug("Found segments for instance: %s" % rows)
        if rows:
            segment_name = rows[0][1]
        else:
            msg = "Cannot find romanaSegment value for mac_address %s." % mac
            raise exceptions.RomanaException(msg)
            #raise ipam_exc.IpAddressGenerationFailure()
        LOG.debug("segment_id: %s" % segment_name)
        if ip_dict.get('ip_address'):
            return ipam_req.SpecificAddressRequest(ip_dict['ip_address'])
        elif ip_dict.get('eui64_address'):
            return ipam_req.AutomaticAddressRequest(
                prefix=ip_dict['subnet_cidr'],
                mac=ip_dict['mac'])
        else:
            return RomanaAnyAddressRequest(
                port.get('binding:host_id'),
                port.get('tenant_id'),
                segment_name)

class RomanaAnySubnetRequest(ipam_req.AnySubnetRequest):
    """A template for allocating an unspecified subnet from IPAM."""

    WILDCARDS = {constants.IPv4: '0.0.0.0',
                 constants.IPv6: '::'}

    def __init__(self, tenant_id, subnet_id, version, prefixlen,
                 gateway_ip=None, allocation_pools=None):
        """Initialize RomanaAnySubnetRequest.

        :param version: Either constants.IPv4 or constants.IPv6
        :param prefixlen: The prefix len requested.  Must be within the
               min and max allowed.
        :type prefixlen: int
        """
        super(RomanaAnySubnetRequest, self).__init__(
            tenant_id=tenant_id,
            subnet_id=subnet_id,
            gateway_ip=gateway_ip,
            allocation_pools=allocation_pools)
        net = netaddr.IPNetwork(self.WILDCARDS[version] + '/' + str(prefixlen))
        self._validate_with_subnet(net)
        self._prefixlen = prefixlen

    @property
    def prefixlen(self):
        """Return Prefix Length."""
        return self._prefixlen


class RomanaSubnetRequestFactory(ipam_req.SubnetRequestFactory):
    """Builds request using subnet information."""

    @classmethod
    def get_request(cls, context, subnet, subnetpool):
        """Return RomanaAnySubnetRequest."""
        LOG.debug("RomanaSubnetRequestFactory.get_request()")
        cidr = subnet.get('cidr')
        subnet_id = subnet.get('id', uuidutils.generate_uuid())
        is_any_subnetpool_request = not validators.is_attr_set(cidr)

        if is_any_subnetpool_request:
            prefixlen = subnet['prefixlen']
            if not validators.is_attr_set(prefixlen):
                prefixlen = int(subnetpool['default_prefixlen'])

            return RomanaAnySubnetRequest(
                subnet['tenant_id'],
                subnet_id,
                common_utils.ip_version_from_int(subnetpool['ip_version']),
                prefixlen)
        else:
            return ipam_req.SpecificSubnetRequest(subnet['tenant_id'],
                                                  subnet_id,
                                                  cidr,
                                                  subnet.get('gateway_ip'),
                                                  subnet.get(
                                                      'allocation_pools'))


class RomanaDbPool(subnet_alloc.SubnetAllocator):
    """Class for handling allocation of subnet prefixes from a subnet pool."""

    def get_address_request_factory(self):
        """Return RomanaAddressRequestFactory."""
        LOG.debug("RomanaDbPool.get_address_request_factory")
        return RomanaAddressRequestFactory

    def get_subnet_request_factory(self):
        """Return RomanaSubnetRequestFactory."""
        LOG.debug("RomanaDbPool.get_subnet_request_factory()")
        return RomanaSubnetRequestFactory

    def get_subnet(self, subnet_id):
        """Retrieve an IPAM subnet.

        :param subnet_id: Neutron subnet identifier
        :returns: a RomanaDbSubnet instance
        """
        LOG.debug("RomanaDbPool.get_subnet(%s)" % subnet_id)
        return RomanaDbSubnet.load(subnet_id, self._context)

    def allocate_subnet(self, subnet_request):
        """Create an IPAM Subnet object for the provided cidr.

        :param cidr: subnet's CIDR
        :returns: a RomanaDbSubnet instance
        """
        LOG.debug("RomanaDbPool.allocate_subnet(%s)" % subnet_request)
        if not isinstance(subnet_request, ipam_req.SpecificSubnetRequest):
            raise ipam_exc.InvalidSubnetRequestType(
                subnet_type=type(subnet_request))
        return RomanaDbSubnet.create_from_subnet_request(subnet_request,
                                                         self._context)

    def update_subnet(self, subnet_request):
        """Update subnet info the in the IPAM driver.

        The only update subnet information the driver needs to be aware of
        are allocation pools.
        """
        LOG.debug("RomanaDbPool.update_subnet(%s)" % subnet_id)
        if not subnet_request.subnet_id:
            raise ipam_exc.InvalidSubnetRequest(
                reason=("An identifier must be specified when updating "
                        "a subnet"))
        if not subnet_request.allocation_pools:
            LOG.debug("Update subnet request for subnet %s did not specify "
                      "new allocation pools, there is nothing to do",
                      subnet_request.subnet_id)
            return
        subnet = RomanaDbSubnet.load(subnet_request.subnet_id, self._context)
        subnet.update_allocation_pools(subnet_request.allocation_pools)
        return subnet

    def remove_subnet(self, subnet_id):
        """Remove data structures for a given subnet."""
        LOG.debug("RomanaDbPool.remove_subnet(%s)" % subnet_id)
