# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Arvind Somya, Cisco Systems, Inc.(asomya@cisco.com)
#
"""
This module will export the configuration parameters
from the n1kv.ini file
"""

from quantum.common.utils import find_config_file
from quantum.plugins.cisco.common import cisco_configparser as confp


CP = confp.CiscoConfigParser(find_config_file({'plugin': 'cisco'},
                             "n1kv.ini"))
N1KV = CP['N1KV']
