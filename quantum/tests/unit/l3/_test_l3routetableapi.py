# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011, Cisco Systems, Inc.
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
#    @author: Shubhangi Satras, Cisco Systems, Inc.
""" Class for routetable API test cases"""
import logging


import quantum.tests.unit.l3.testlib_l3routetableapi as testlib

from quantum.tests.unit.l3._test_l3api import L3AbstractAPITest
from quantum.wsgi import XMLDeserializer, JSONDeserializer

LOG = logging.getLogger(__name__)

RESPONSE_CODE_ROUTETABLE_NOTFOUND = 460

ROUTETABLES = 'routetables'


class L3RoutetableAbstractAPITest(L3AbstractAPITest):
    """This class contains test cases for routetable API"""

    def _test_unparsable_data(self, req_format):
        """ Tests unparsable data"""
        LOG.debug("_test_unparsable_data - " \
                  " req_format:%s - START", req_format)
        data = "this is not json or xml"
        method = 'POST'
        content_type = "application/%s" % req_format
        tenant_id = self.tenant_id
        LOG.debug("tenant_id: %s", tenant_id)
        path = "/tenants/%(tenant_id)s/routetables.%(req_format)s" % locals()
        routetable_req = testlib.create_request(path, data, content_type,
                                                method)
        routetable_res = routetable_req.get_response(self.api)
        self.assertEqual(routetable_res.status_int, 400)

        LOG.debug("_test_unparsable_data - " \
                  "req_format:%s - END", req_format)

    def _create_routetable(self, req_format, custom_req_body=None,
                        expected_res_status=202):
        """ Creates routetable and returns the generated routable id"""
        LOG.debug("Creating routetable")
        content_type = "application/" + req_format
        routetable_req = testlib.new_routetable_request(self.tenant_id,
                                                  req_format,
                                                  custom_req_body)
        routetable_res = routetable_req.get_response(self.api)
        self.assertEqual(routetable_res.status_int, expected_res_status)
        if expected_res_status in (202, 200):
            routetable_data = self._routetable_deserializers[content_type].\
                    deserialize(routetable_res.body)['body']
            return routetable_data['routetable']['id']

    def _test_create_routetable(self, req_format):
        """Tests creation of routetable"""
        LOG.debug("_test_create_routetable- req_format:%s - START", req_format)
        content_type = "application/%s" % req_format
        routetable_id = self._create_routetable(req_format)
        show_routetable_req = testlib.show_routetable_request(self.tenant_id,
                                                        routetable_id,
                                                        req_format)
        show_routetable_res = show_routetable_req.get_response(self.api)
        self.assertEqual(show_routetable_res.status_int, 200)
        routetable_data = self._routetable_deserializers[content_type].\
                deserialize(show_routetable_res.body)['body']
        self.assertEqual(routetable_id, routetable_data['routetable']['id'])
        LOG.debug("_test_create_routetable - req_format:%s - END", req_format)

    def _test_create_routetable_badrequest(self, req_format):
        """Tests creation of routetable when bad request is sent """
        LOG.debug("_test_create_routetable_badrequest - req_format:%s - START",
                  req_format)
        bad_body = {'bad-attribute': {'bad-attribute': 'very-bad'}}
        self._create_routetable(req_format, custom_req_body=bad_body,
                             expected_res_status=400)
        LOG.debug("_test_create_routetable_badrequest - req_format:%s - END",
                  req_format)

    def _test_list_routetables(self, req_format):
        """Tests proper listing of routetable """
        LOG.debug("_test_list_routetables - req_format:%s - START", req_format)
        content_type = "application/%s" % req_format
        self._create_routetable(req_format)
        self._create_routetable(req_format)
        list_routetable_req = testlib.routetable_list_request(self.tenant_id,
                                                        req_format)
        list_routetable_res = list_routetable_req.get_response(self.api)
        self.assertEqual(list_routetable_res.status_int, 200)
        routetable_data = self._routetable_deserializers[content_type].\
                deserialize(list_routetable_res.body)['body']
        # Check routetable count: should return 2
        self.assertEqual(len(routetable_data['routetables']), 2)
        LOG.debug("_test_list_routetables - req_format:%s - END", req_format)

    def _test_list_routetables_detail(self, req_format):
        """Tests listing of routetable with each entry indetail """
        LOG.debug("_test_list_routetables_detail - req_format:%s - START",
                   req_format)
        content_type = "application/%s" % req_format
        self._create_routetable(req_format)
  #      self._create_routetable(req_format)
        list_routetable_req = testlib.routetable_list_detail_request(
                                                     self.tenant_id,
                                                     req_format)
        list_routetable_res = list_routetable_req.get_response(self.api)
        self.assertEqual(list_routetable_res.status_int, 200)
        routetable_data = self._routetable_deserializers[content_type].\
                deserialize(list_routetable_res.body)['body']
        # Check routetable count: should return 2
        self.assertEqual(len(routetable_data['routetables']), 1)
        # Check contents - id for each routetable
        for routetable in routetable_data['routetables']:
            self.assertTrue('id' in routetable.keys())
            self.assertTrue(routetable['id'])
        LOG.debug("_test_list_routetables_detail - req_format:%s - END",
                   req_format)

    def _test_show_routetable(self, req_format):
        """Tests show routetable """
        LOG.debug("_test_show_routetable - req_format:%s - START", req_format)
        content_type = "application/%s" % req_format
        routetable_id = self._create_routetable(req_format)
        show_routetable_req = testlib.show_routetable_request(self.tenant_id,
                                                        routetable_id,
                                                        req_format)
        show_routetable_res = show_routetable_req.get_response(self.api)
        self.assertEqual(show_routetable_res.status_int, 200)
        routetable_data = self._routetable_deserializers[content_type].\
                deserialize(show_routetable_res.body)['body']['routetable']
        routetable_data = self._remove_non_attribute_keys(routetable_data)
        self.assertEqual({'id': routetable_id,
                          'description': routetable_data['description'],
                          'label': routetable_data['label']},
                          routetable_data)
        LOG.debug("_test_show_routetable - req_format:%s - END", req_format)

    def _test_show_routetable_detail(self, req_format):
        """Tests show routetable in detail """
        LOG.debug("_test_show_routetable_detail - req_format:%s - START",
                   req_format)
        content_type = "application/%s" % req_format
        # Create a routetable
        routetable_id = self._create_routetable(req_format)
        show_routetable_req = testlib.show_routetable_detail_request(
                                    self.tenant_id, routetable_id, req_format)
        show_routetable_res = show_routetable_req.get_response(self.api)
        self.assertEqual(show_routetable_res.status_int, 200)
        routetable_data = self._routetable_deserializers[content_type].\
                deserialize(show_routetable_res.body)['body']['routetable']
        routetable_data = self._remove_non_attribute_keys(routetable_data)
        self.assertEqual({'id': routetable_id,
                          'description': routetable_data['description'],
                          'label': routetable_data['label']},
                          routetable_data)
        LOG.debug("_test_show_routetable_detail - req_format:%s - END",
                   req_format)

    def _test_show_routetable_not_found(self, req_format):
        """ Tests show routetable when routetable is not found"""
        LOG.debug("_test_show_routetable_not_found - req_format:%s - START", \
                  req_format)
        show_routetable_req = testlib.show_routetable_request(self.tenant_id,
                                                        "A_BAD_ID",
                                                        req_format)
        show_routetable_res = show_routetable_req.get_response(self.api)
        self.assertEqual(show_routetable_res.status_int, 460)
        LOG.debug("_test_show_routetable_not_found - req_format:%s - END",
                  req_format)

    def _test_update_routetable(self, req_format):
        """ Tests updation of routetable"""
        LOG.debug("_test_update_routetable - req_format:%s - START",
                   req_format)
        content_type = "application/%s" % req_format
        new_label = 'new_label'
        routetable_id = self._create_routetable(req_format)
        update_routetable_req = testlib.update_routetable_request(
                                          self.tenant_id,
                                          routetable_id,
                                          new_label,
                                          req_format)
        update_routetable_res = update_routetable_req.get_response(self.api)
        self.assertEqual(update_routetable_res.status_int,
                         204)
        show_routetable_req = testlib.show_routetable_request(self.tenant_id,
                                                        routetable_id,
                                                        req_format)
        show_routetable_res = show_routetable_req.get_response(self.api)
        self.assertEqual(show_routetable_res.status_int, 200)
        routetable_data = self._routetable_deserializers[content_type].\
                deserialize(show_routetable_res.body)['body']['routetable']
        LOG.debug("routetable_data is :%s", routetable_data)
        routetable_data = self._remove_non_attribute_keys(routetable_data)
        self.assertEqual({'id': routetable_id,
                          'label': new_label,
                          'description': routetable_data['description']},
                          routetable_data)
        LOG.debug("_test_update_routetable - req_format:%s - END", req_format)

    def _test_update_routetable_badrequest(self, req_format):
        """ Tests updation of routetable when bad request is sent"""
        LOG.debug("_test_update_routetable_badrequest - req_format:%s - START",
                  req_format)
        routetable_id = self._create_routetable(req_format)
        label = 'bad_label'
        bad_body = {'bad-attribute': {'bad-attribute': 'very-bad'}}
        update_routetable_req = testlib.\
                             update_routetable_request(self.tenant_id,
                                                    routetable_id, label,
                                                    req_format,
                                                    custom_req_body=bad_body)
        update_routetable_res = update_routetable_req.get_response(self.api)
        self.assertEqual(update_routetable_res.status_int, 400)
        LOG.debug("_test_update_routetable_badrequest - req_format:%s - END",
                  req_format)

    def _test_update_routetable_not_found(self, req_format):
        """ Tests updation of routetable when routetable doesnot exist"""
        LOG.debug("_test_update_routetable_not_found - req_format:%s - START",
                  req_format)
        label = 'label'
        update_routetable_req = testlib.update_routetable_request(
                                                   self.tenant_id,
                                                   "A BAD ID",
                                                   label,
                                                   req_format)
        update_routetable_res = update_routetable_req.get_response(self.api)
        self.assertEqual(update_routetable_res.status_int, 460)
        LOG.debug("_test_update_routetable_not_found - req_format:%s - END",
                  req_format)

    def _test_delete_routetable(self, req_format):
        """ Tests the deletion of the routetable"""
        LOG.debug("_test_delete_routetable - req_format:%s - START",
                   req_format)
        content_type = "application/%s" % req_format
        routetable_id = self._create_routetable(req_format)
        LOG.debug("Deleting routetable %s"\
                  " of tenant %s" % (routetable_id, self.tenant_id))
        delete_routetable_req = testlib.routetable_delete_request(
                                                   self.tenant_id,
                                                   routetable_id,
                                                   req_format)
        delete_routetable_res = delete_routetable_req.get_response(self.api)
        self.assertEqual(delete_routetable_res.status_int,
                         204)
        delete_routetable_req = testlib.routetable_delete_request(
                                                    self.tenant_id,
                                                    routetable_id,
                                                    req_format)
        delete_routetable_res = delete_routetable_req.get_response(self.api)
        self.assertEqual(delete_routetable_res.status_int,
                         RESPONSE_CODE_ROUTETABLE_NOTFOUND)
        LOG.debug("_test_delete_routetable - req_format:%s - END", req_format)

    def setUp(self, api_router_klass, xml_metadata_dict):
        """This is a setUp procedure used for the setting up the parameters."""
        super(L3RoutetableAbstractAPITest, self).setUp(api_router_klass,
                                                   xml_metadata_dict)
        self.tenant_id = "test_tenant"
        # Prepare XML & JSON deserializers
        routetable_xml_deserializer = XMLDeserializer(
                                      xml_metadata_dict[ROUTETABLES])

        json_deserializer = JSONDeserializer()

        self._routetable_deserializers = {
            'application/xml': routetable_xml_deserializer,
            'application/json': json_deserializer,
        }

    def tearDown(self):
        """Clear the test environment"""
        super(L3RoutetableAbstractAPITest, self).tearDown()

    def test_list_routetables_json(self):
        """Tests listing of routetable for json as request """
        self._test_list_routetables('json')

    def test_list_routetables_xml(self):
        """Tests listing of routetable for xml as request """
        self._test_list_routetables('xml')

    def test_list_routetables_detail_json(self):
        """Tests listing of routetable with each entry for json as request """
        self._test_list_routetables_detail('json')

    def test_list_routetables_detail_xml(self):
        """Tests listing of routetable with each entry for xml as request """
        self._test_list_routetables_detail('xml')

    def test_create_routetable_json(self):
        """Tests creation of routetable for json as request """
        self._test_create_routetable('json')

    def test_create_routetable_xml(self):
        """Tests creation of routetable for xml as request """
        self._test_create_routetable('xml')

    def test_create_routetable_badrequest_json(self):
        """Tests creation of routetable for json as bad request """
        self._test_create_routetable_badrequest('json')

    def test_create_routetable_badrequest_xml(self):
        """Tests creation of routetable for xml as bad request """
        self._test_create_routetable_badrequest('xml')

    def test_show_routetable_not_found_json(self):
        """Tests show routetable for json req_format """
        self._test_show_routetable_not_found('json')

    def test_show_routetable_not_found_xml(self):
        """Tests show routetable for xml req_format"""
        self._test_show_routetable_not_found('xml')

    def test_show_routetable_json(self):
        """Tests show routetable for json format request"""
        self._test_show_routetable('json')

    def test_show_routetable_xml(self):
        """Tests show routetable with request sent in xml format"""
        self._test_show_routetable('xml')

    def test_show_routetable_detail_json(self):
        """Tests show routetable in detail with request sent in json format"""
        self._test_show_routetable_detail('json')

    def test_show_routetable_detail_xml(self):
        """Tests show routetable in detail with request sent in xml format"""
        self._test_show_routetable_detail('xml')

    def test_delete_routetable_json(self):
        """Tests deletion of routetable in with request sent in json format"""
        self._test_delete_routetable('json')

    def test_delete_routetable_xml(self):
        """Tests deletion of routetable with request sent in xml format"""
        self._test_delete_routetable('xml')

    def test_update_routetable_json(self):
        """Tests updation of routetable with request sent in json format"""
        self._test_update_routetable('json')

    def test_update_routetable_xml(self):
        """Tests updation of routetable with request sent in xml format"""
        self._test_update_routetable('xml')

    def test_update_routetable_not_found_json(self):
        """Tests updation with request sent with non-existing routetable"""
        self._test_update_routetable_not_found('json')

    def test_update_routetable_not_found_xml(self):
        """Tests updation with request sent with non-existing routetable"""
        self._test_update_routetable_not_found('xml')

    def test_update_routetable_badrequest_json(self):
        """Tests updation with bad request sent in json format"""
        self._test_update_routetable_badrequest('json')

    def test_update_routetable_badrequest_xml(self):
        """Tests updation with bad request sent in xml format"""
        self._test_update_routetable_badrequest('xml')

    def test_unparsable_data_xml(self):
        """ Tests unparasable data with request sent in xml format"""
        self._test_unparsable_data('xml')

    def test_unparsable_data_json(self):
        """Tests unparasable data with request sent in json format"""
        self._test_unparsable_data('json')
