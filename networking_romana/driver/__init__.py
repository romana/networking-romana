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

from oslo_config import cfg
from oslo_log import log

LOG = log.getLogger(__name__)
LOG.debug("Loading Configuration for Romana.")

romana_opts = [
    cfg.StrOpt('ipam_url', default=None, help=_('IPAM URL.')),
    cfg.StrOpt('root_url', default=None,
               help=_('Romana Root Service Manager URL.')),
    cfg.IntOpt('root_port', default='9600',
               help=_('Romana Root Service Port Number.')),
    cfg.IntOpt('ipam_port', default='9601',
               help=_('Romana IPAM Service Port Number.')),
    cfg.IntOpt('tenant_port', default='9602',
               help=_('Romana Tenant Service Port Number.')),
    cfg.IntOpt('topology_port', default='9603',
               help=_('Romana Topology Service Port Number.')),
    cfg.IntOpt('agent_port', default='9604',
               help=_('Romana Agent Service Port Number.')),
]

LOG.debug("Registering Romana configuration options.")
cfg.CONF.register_opts(romana_opts, 'romana')
