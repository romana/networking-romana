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

from neutron_lib import exceptions


class RomanaException(exceptions.NeutronException):
    """Generic Romana exception."""
    message = "RomanaException: '%(msg)s'"

    def __init__(self, msg):
        kwargs = {'msg': msg}
        self.msg = self.message % kwargs
        super(RomanaException, self).__init__(**kwargs)

    def __str__(self):
        return self.msg


class RomanaAgentConnectionException(exceptions.NeutronException):
    message = "Failed connecting to Romana Agent at URL: %(url)s with data %(data)s: %(msg)s"

    def __init__(self, url, data, msg):
        kwargs = {'msg': str(msg), 'url': url, 'data': str(data)}
        self.msg = self.message % kwargs
        super(RomanaAgentConnectionException, self).__init__(**kwargs)

    def __str__(self):
        return self.msg
