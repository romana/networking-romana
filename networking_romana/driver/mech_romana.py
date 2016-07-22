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

from oslo_config import cfg
from oslo_log import log

from neutron.agent import securitygroups_rpc
from neutron.common import constants
from neutron.extensions import portbindings as pb
from neutron.i18n import _LI
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from six.moves.urllib.parse import urlencode
from six.moves.urllib.request import Request
from six.moves.urllib.request import urlopen

from networking_romana.driver import exceptions, utils

LOG = log.getLogger(__name__)

VIF_TYPE_TAP = 'tap'


class RomanaMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Neutron/ML2 mechanism driver for Project Romana.

    The RomanaMechanismDriver integrates the ml2 plugin with the
    Romana Networking Services. It provides a way to allocate
    Romana segment addresses.
    """

    def __init__(self):
        LOG.debug("Initializing Mech Driver.")
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        self.vif_type = VIF_TYPE_TAP
        self.vif_details = {pb.CAP_PORT_FILTER: sg_enabled}
        self.supported_network_types = [p_constants.TYPE_LOCAL,
                                        p_constants.TYPE_FLAT]
        super(RomanaMechanismDriver, self).__init__(
            constants.AGENT_TYPE_DHCP,
            self.vif_type,
            self.vif_details)
        LOG.debug("Initialized Mech Driver.")

    def get_allowed_network_types(self, agent=None):
        LOG.debug("Allowed network types: %s" %
                  self.supported_network_types)
        return self.supported_network_types

    def get_mappings(self, agent):
        LOG.debug("Get Mappings.")
        pass

    def check_segment_for_agent(self, segment, agent):
        LOG.debug("segment: %s, agent: %s" % (segment, agent))
        if segment[api.NETWORK_TYPE] in self.supported_network_types:
            return True
        else:
            return False

    def check_vlan_transparency(self, context):
        """Currently Romana driver doesn't support vlan transparency."""
        LOG.debug("check_vlan_transparency")
        return False

    def create_network_precommit(self, context):
        LOG.debug("create_network_precommit")
        pass

    def create_network_postcommit(self, context):
        LOG.debug("create_network_postcommit")
        pass

    def update_network_precommit(self, context):
        LOG.debug("update_network_precommit")
        pass

    def update_network_postcommit(self, context):
        LOG.debug("update_network_postcommit")
        pass

    def delete_network_precommit(self, context):
        LOG.debug("delete_network_precommit")
        pass

    def delete_network_postcommit(self, context):
        LOG.debug("delete_network_postcommit")
        pass

    def create_subnet_precommit(self, context):
        LOG.debug("create_subnet_precommit")
        pass

    def create_subnet_postcommit(self, context):
        LOG.debug("create_subnet_postcommit")
        pass

    def update_subnet_precommit(self, context):
        LOG.debug("update_subnet_precommit")
        pass

    def update_subnet_postcommit(self, context):
        LOG.debug("update_subnet_postcommit")
        pass

    def delete_subnet_precommit(self, context):
        LOG.debug("delete_subnet_precommit")
        pass

    def delete_subnet_postcommit(self, context):
        LOG.debug("delete_subnet_postcommit")
        pass

    def create_port_precommit(self, context):
        LOG.debug("create_port_precommit")
        pass

    def create_port_postcommit(self, context):
        LOG.debug("create_port_postcommit")
        pass

    def update_port_precommit(self, context):
        LOG.debug("update_port_precommit")
        pass

    def update_port_postcommit(self, context):
        """Update a port.

        :param context: PortContext instance describing the new
        state of the port, as well as the original state prior
        to the update_port call.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.

        update_port_postcommit is called for all changes to the port
        state. It is up to the mechanism driver to ignore state or
        state changes that it does not know or care about.

        Send info to romana agent.
        """
        LOG.debug("Romana mech driver: update_port_postcommit")

        if port_status_only_request(context.current, context.original):
            return

        port = context.current
        if (port[pb.VIF_TYPE] != pb.VIF_TYPE_UNBOUND and
                context.original[pb.VIF_TYPE] == pb.VIF_TYPE_UNBOUND):
            port['interface_name'] = 'tap' + port['id'][:11]
            agent_port = utils.find_agent_port(cfg.CONF.romana.url)
            url = 'http://{0}:{1}/vm'.format(port[pb.HOST_ID], agent_port)
            data = {'interface_name': port['interface_name'],
                    'mac_address': port['mac_address'],
                    'ip_address':
                    port['fixed_ips'][0]['ip_address']}
            LOG.debug("Romana mech driver: Agent full url: %s/%s" % (url, data))
            try:
                res = utils.http_call('POST', url, data)
                LOG.debug("Romana mech driver: Agent response: %s" % res)
            except exceptions.RomanaException:
                raise
            except Exception as e:
                LOG.debug("Romana mech driver: Error in GET %s with %s: %s", url, data, e)
                raise exceptions.RomanaAgentConnectionException(url, data, e)

    def bind_port(self, context):
        """Attempt to bind a port.

        :param context: PortContext instance describing the port

        This method is called outside any transaction to attempt to
        establish a port binding using this mechanism driver. Bindings
        may be created at each of multiple levels of a hierarchical
        network, and are established from the top level downward. At
        each level, the mechanism driver determines whether it can
        bind to any of the network segments in the
        context.segments_to_bind property, based on the value of the
        context.host property, any relevant port or network
        attributes, and its own knowledge of the network topology. At
        the top level, context.segments_to_bind contains the static
        segments of the port's network. At each lower level of
        binding, it contains static or dynamic segments supplied by
        the driver that bound at the level above. If the driver is
        able to complete the binding of the port to any segment in
        context.segments_to_bind, it must call context.set_binding
        with the binding details. If it can partially bind the port,
        it must call context.continue_binding with the network
        segments to be used to bind at the next lower level.

        If the binding results are committed after bind_port returns,
        they will be seen by all mechanism drivers as
        update_port_precommit and update_port_postcommit calls. But if
        some other thread or process concurrently binds or updates the
        port, these binding results will not be committed, and
        update_port_precommit and update_port_postcommit will not be
        called on the mechanism drivers with these results. Because
        binding results can be discarded rather than committed,
        drivers should avoid making persistent state changes in
        bind_port, or else must ensure that such state changes are
        eventually cleaned up.

        Implementing this method explicitly declares the mechanism
        driver as having the intention to bind ports. This is inspected
        by the QoS service to identify the available QoS rules you
        can use with ports.
        """
        LOG.debug("bind_port")

        segments = context.network.network_segments
        for segment in segments:
            if segment[api.NETWORK_TYPE] in self.supported_network_types:
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details,
                                    status=constants.PORT_STATUS_ACTIVE)
                LOG.debug("Port binding set for segment ID %(id)s, "
                          "segment %(segment)s and network type "
                          "%(nettype)s",
                          {'id': segment[api.ID],
                           'segment': segment[api.SEGMENTATION_ID],
                           'nettype': segment[api.NETWORK_TYPE]})
                return
            else:
                LOG.info(_LI("Port binding ignored for segment ID %(id)s, "
                             "segment %(segment)s and network type "
                             "%(nettype)s"),
                         {'id': segment[api.ID],
                          'segment': segment[api.SEGMENTATION_ID],
                          'nettype': segment[api.NETWORK_TYPE]})

    def delete_port_precommit(self, context):
        LOG.debug("delete_port_precommit")
        pass

    def delete_port_postcommit(self, context):
        LOG.debug("delete_port_postcommit")
        pass


def port_status_only_request(current, original):
    LOG.debug("port_status_only_request")
    ignore_values = ('status')
    p1, p2 = current.copy(), original.copy()
    for k in ignore_values:
        try:
            del p1[k]
        except KeyError:
            pass
        try:
            del p2[k]
        except KeyError:
            pass
    return p1 == p2
