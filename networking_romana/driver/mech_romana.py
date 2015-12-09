# Copyright (c) 2015 Pani Networks Inc
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

from oslo_log import log

from neutron.agent import securitygroups_rpc
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_constants
from neutron.plugins.ml2.drivers import mech_agent

LOG = log.getLogger(__name__)

AGENT_TYPE_ROMANA = "Romana Agent"
VIF_TYPE_TAP = 'tap'


class RomanaMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Neutron/ML2 mechanism driver for Project Romana.

    The RomanaMechanismDriver integrates the ml2 plugin with the
    Romana Networking Services. It provides a way to allocate
    Romana segment addresses.
    """

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        super(RomanaMechanismDriver, self).__init__(
            AGENT_TYPE_ROMANA,
            VIF_TYPE_TAP,
            {portbindings.CAP_PORT_FILTER: sg_enabled})

    def get_allowed_network_types(self, agent=None):
        return [p_constants.TYPE_LOCAL, p_constants.TYPE_FLAT]

    def get_mappings(self, agent):
        pass
