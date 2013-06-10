# Copyright (c) 2013 OpenStack Foundation
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

from quantum.common import exceptions as exc
from quantum.openstack.common import log
from quantum.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)

TYPE_LOCAL = 'local'


class LocalTypeDriver(api.TypeDriver):
    """Manage state for local networks with ML2.

    The LocalTypeDriver implements the 'local' network_type. Local
    network segments provide connectivity between VMs and other
    devices running on the same node, provided that a common local
    network bridging technology is available to those devices. Local
    network segments do not provide any connectivity between nodes.
    """

    def __init__(self):
        LOG.info(_("ML2 LocalTypeDriver initialization complete"))

    def get_type(self):
        return TYPE_LOCAL

    def initialize(self):
        pass

    def validate_provider_segment(self, segment):
        for key, value in segment.iteritems():
            if value and key not in [api.NETWORK_TYPE]:
                msg = _("%s prohibited for local provider network") % key
                raise exc.InvalidInput(error_message=msg)

        return segment

    def reserve_provider_segment(self, session, segment):
        # No resources to reserve
        pass

    def allocate_tenant_segment(self, session):
        # No resources to allocate
        return {api.NETWORK_TYPE: TYPE_LOCAL}

    def release_segment(self, session, segment):
        # No resources to release
        pass
