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

import netaddr

from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils

from neutron.extensions import portbindings as pb
from neutron.common import utils as common_utils
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from neutron.ipam import driver as ipam_base
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req
from neutron.ipam import subnet_alloc

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
        plugin = directory.get_plugin()
        neutron_subnet = plugin._get_subnet(ctx, neutron_subnet_id)
        retval = cls(neutron_subnet_id,
                     ctx,
                     cidr=neutron_subnet['cidr'],
                     gateway_ip=neutron_subnet['gateway_ip'],
                     tenant_id=neutron_subnet['tenant_id'],
                     subnet_id=neutron_subnet_id)
        return retval
    
    def allocate(self, address_request):
        """Allocate Address by calling Romana IPAM Agent."""

        LOG.debug("RomanaDbSubnet.allocate(%s)" % vars(address_request))

        if isinstance(address_request, ipam_req.SpecificAddressRequest):
            msg = "Specific address allocation not supported by Romana."
            raise exceptions.RomanaException(msg)

        name = address_request.port_id
        host = address_request.host_name
        tenant = address_request.tenant_id
        segment = address_request.segment_name
        try:
            ip = utils.romana_allocate_ip_address(self.romana_url, name, tenant, segment, host)
            LOG.debug("Romana IPAM: IP(%s) successfully assigned for host(%s), tenant(%s), segment(%s)",
                      ip, host, tenant,segment)
        except Exception as e:
            raise exceptions.RomanaException(
                "Error allocating IP for host(%s), tenant(%s), segment(%s): %s" %
                (host, tenant, segment, e))
        return ip

    def deallocate(self, address):
        """Deallocate the IPAddress by calling Romana Daemon"""
        LOG.debug("RomanaDbSubnet.deallocate(%s)" % address)
        try:
            resp = utils.romana_deallocate_ip_address(self.romana_url, address)
        except Exception as e:
            raise exceptions.RomanaException("Error deallocating IP, error(%s)" % e)

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


class RomanaAnyAddressRequest(ipam_req.AnyAddressRequest):
    """Used to request any available address from the pool."""

    def __init__(self, host_name, tenant_id, port_id, segment_name):
        """Initialize RomanaAnyAddressRequest."""
        super(ipam_req.AnyAddressRequest, self).__init__()
        self.host_name = host_name
        self.tenant_id = tenant_id
        self.segment_name = segment_name
        self.port_id = port_id
        LOG.debug("RomanaAnyAddressRequest: host_name: %s", host_name)
        LOG.debug("RomanaAnyAddressRequest: tenant_id: %s", tenant_id)
        LOG.debug("RomanaAnyAddressRequest: segment_name: %s", segment_name)
        LOG.debug("RomanaAnyAddressRequest: port_id: %s", port_id)


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

        # Use default segment for now, later use metadata tags for this.
        romana_segment_name = "default"

        if ip_dict.get('ip_address'):
            return ipam_req.SpecificAddressRequest(ip_dict['ip_address'])
        elif ip_dict.get('eui64_address'):
            return ipam_req.AutomaticAddressRequest(
                prefix=ip_dict['subnet_cidr'],
                mac=ip_dict['mac'])
        else:
            return RomanaAnyAddressRequest(
                port.get(pb.HOST_ID),
                port.get('tenant_id'),
                port.get('id'),
                romana_segment_name)


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
            version=version,
            prefixlen=prefixlen,
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
        LOG.debug("RomanaDbPool.allocate_subnet(%s)" % vars(subnet_request))
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
        LOG.debug("RomanaDbPool.update_subnet(%s)" % subnet_request)
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
