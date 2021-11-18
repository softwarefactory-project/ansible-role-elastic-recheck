#!/usr/bin/env python3
#
# Copyright (C) 2021 Red Hat
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import json
import pytest
import requests
import yaml

logger = logging.getLogger(__name__)

with open('tests/config.yml', 'r') as opensearch_creds:
    configuration = yaml.safe_load(opensearch_creds)


def _convert_name(v):
    return v.replace('.', '_')


def _get_user_for_role(role):
    for usr in configuration['users']:
        if usr.get('role') == role:
            user = _convert_name("%s_%s" % (usr['user'], usr['tenant']))
            tenant = _convert_name(usr['tenant'])
            return user, usr['password'], tenant


class TestClassSingleTenant:
    # user is kibana readonly user for specified tenant
    user, user_pass, user_tenant = _get_user_for_role('readonly')
    admin, admin_pass, admin_tenant = _get_user_for_role('admin')
    opensearch_api_url = configuration['opensearch_api_url']
    insecure = not configuration['insecure']

    fake_index = 'fakeindex'
    index_pattern = "logstash-" + user_tenant + "-test"

    user_session = requests.Session()
    user_session.auth = (user, user_pass)

    admin_session = requests.Session()
    admin_session.auth = (admin, admin_pass)

    def _create_index(self, index):
        url = "%s/%s" % (self.opensearch_api_url, index)
        r = self.admin_session.put(url, verify=self.insecure)
        return r.status_code == 200

    def _delete_index(self, index):
        url = "%s/%s" % (self.opensearch_api_url, index)
        r = self.admin_session.delete(url, verify=self.insecure)
        assert r.status_code == 200

    def _prepare_query(self, indexes):
        pass

    def _make_query(self, url, index,
                    user_method, admin_method, user_status_code,
                    admin_status_code, data=None, headers=None):

        kwargs = {'verify': self.insecure}
        if data:
            kwargs['data'] = json.dumps(data)
        if headers:
            kwargs['headers'] = headers

        try:
            if index and not self._create_index(index):
                pytest.fail('Can not create index')

            user = user_method(url, **kwargs)
            admin = admin_method(url, **kwargs)

            assert user.status_code == user_status_code
            assert admin.status_code == admin_status_code
        finally:
            if index:
                self._delete_index(index)

    def test_login_without_creds(self):
        r = requests.get(self.opensearch_api_url, verify=self.insecure)
        assert r.status_code == 401

    def test_login_fake_creds(self):
        session = requests.Session()
        session.auth = ('kibana', 'kibana')
        r = session.get(self.opensearch_api_url, verify=self.insecure)
        assert r.status_code == 401

    def test_no_index_specified(self):
        r = self.user_session.get(self.opensearch_api_url,
                                  verify=self.insecure)
        assert r.status_code == 403
        r = self.admin_session.get(self.opensearch_api_url,
                                   verify=self.insecure)
        assert r.status_code == 200

    # Check: <url>/_cat/indices
    def test_get_indices(self):
        url = "%s/_cat/indices" % self.opensearch_api_url
        r = self.user_session.get(url, verify=self.insecure)
        assert r.status_code == 403
        r = self.admin_session.get(url, verify=self.insecure)
        assert r.status_code == 200

    def test_create_index(self):
        url = "%s/%s" % (self.opensearch_api_url, self.index_pattern)
        r = self.user_session.put(url, verify=self.insecure)
        assert r.status_code == 403
        r = self.admin_session.put(url, verify=self.insecure)
        assert r.status_code == 200

    def test_delete_index(self):
        url = "%s/%s" % (self.opensearch_api_url, self.index_pattern)
        r = self.user_session.delete(url, verify=self.insecure)
        assert r.status_code == 403
        r = self.admin_session.delete(url, verify=self.insecure)
        assert r.status_code == 200

    def test_create_index_user_delete(self):
        try:
            if not self._create_index(self.index_pattern):
                pytest.fail('Can not create index')
            url = "%s/%s" % (self.opensearch_api_url, self.index_pattern)
            r = self.user_session.delete(url, verify=self.insecure)
            assert r.status_code == 403
        finally:
            self._delete_index(self.index_pattern)

    def test_read_index_settings(self):
        url = "%s/%s/_settings" % (self.opensearch_api_url, self.index_pattern)
        self._make_query(url, self.index_pattern, self.user_session.get,
                         self.admin_session.get, 403, 200)

    def test_update_index_settings(self):
        url = "%s/%s/_settings" % (self.opensearch_api_url,
                                   self.index_pattern)
        data = {'index': {'number_of_replicas': 2}}
        headers = {'Content-type': 'application/json'}
        self._make_query(url, self.index_pattern, self.user_session.put,
                         self.admin_session.put, 403, 200, data, headers)

    def test_read_secure_index(self):
        index = None
        url = "%s/.kibana_1" % self.opensearch_api_url
        self._make_query(url, index, self.user_session.get,
                         self.admin_session.get, 403, 200)
        # FIXME: remove when opensearch remove that indices.
        url = "%s/.opendistro_security" % self.opensearch_api_url
        self._make_query(url, index, self.user_session.get,
                         self.admin_session.get, 403, 200)

    def test_read_index_mapping(self):
        url = "%s/%s/_mapping" % (self.opensearch_api_url, self.index_pattern)
        self._make_query(url, self.index_pattern, self.user_session.get,
                         self.admin_session.get, 403, 200)

    def test_update_index_mapping(self):
        data = {'properties': {'email': {'type': 'keyword'}}}
        headers = {'Content-type': 'application/json'}
        url = "%s/%s/_mapping" % (self.opensearch_api_url, self.index_pattern)
        self._make_query(url, self.index_pattern,
                         self.user_session.put, self.admin_session.put,
                         403, 200, data, headers)

    def test_update_multiple_targets_mapping(self):
        try:
            index2 = 'fakeindex2'
            if not self._create_index(self.index_pattern):
                pytest.fail('Can not create index %s' % self.index_pattern)
            if not self._create_index(index2):
                pytest.fail('Can not create index %s' % index2)

            data = {'properties': {
                'user': {
                    'properties': {
                        'name': {
                            'type': 'keyword'
                        }
                    }
                }}
            }
            headers = {'Content-type': 'application/json'}
            url = "%s/%s,%s/_mapping" % (self.opensearch_api_url,
                                         self.index_pattern,
                                         index2)
            r = self.user_session.put(url, verify=self.insecure,
                                      headers=headers, data=json.dumps(data))
            assert r.status_code == 403

            r = self.admin_session.put(url, verify=self.insecure,
                                       headers=headers, data=json.dumps(data))
            assert r.status_code == 200
        finally:
            self._delete_index(self.index_pattern)
            self._delete_index(index2)

    def test_read_indices_stats(self):
        url = "%s/_stats" % (self.opensearch_api_url)
        self._make_query(url, self.index_pattern,
                         self.user_session.get, self.admin_session.get,
                         403, 200)
        index = 'fakeindex'
        url = "%s/%s/_stats" % (self.opensearch_api_url, index)
        self._make_query(url, index, self.user_session.get,
                         self.admin_session.get, 403, 200)

        url = "%s/%s/_stats" % (self.opensearch_api_url, self.index_pattern)
        self._make_query(url, self.index_pattern, self.user_session.get,
                         self.admin_session.get, 200, 200)

    def test_read_segments(self):
        url = "%s/%s/_segments" % (self.opensearch_api_url, self.index_pattern)
        self._make_query(url, self.index_pattern,
                         self.user_session.get, self.admin_session.get,
                         403, 200)

    def test_read_recovery(self):
        index = 'fakeindex'
        url = "%s/%s/_recovery" % (self.opensearch_api_url, index)
        self._make_query(url, index, self.user_session.get,
                         self.admin_session.get, 403, 200)
        # for logstash-sftests_com-* is allowed
        url = "%s/%s/_recovery" % (self.opensearch_api_url, self.index_pattern)
        self._make_query(url, self.index_pattern, self.user_session.get,
                         self.admin_session.get, 200, 200)

    def test_read_shards_stores(self):
        url = "%s/%s/_shard_stores" % (self.opensearch_api_url,
                                       self.index_pattern)
        f_url = "%s/%s/_shard_stores" % (self.opensearch_api_url,
                                         self.fake_index)
        self._make_query(url, self.index_pattern,
                         self.user_session.get, self.admin_session.get,
                         403, 200)
        self._make_query(f_url, self.fake_index, self.user_session.get,
                         self.admin_session.get, 403, 200)

    def test_run_clear_cache(self):
        url = "%s/%s/_cache/clear" % (self.opensearch_api_url,
                                      self.index_pattern)
        f_url = "%s/%s/_cache/clear" % (self.opensearch_api_url,
                                        self.fake_index)
        self._make_query(url, self.index_pattern,
                         self.user_session.post, self.admin_session.post,
                         403, 200)
        self._make_query(f_url, self.fake_index, self.user_session.post,
                         self.admin_session.post, 403, 200)

    def test_run_refresh(self):
        url = "%s/%s/_refresh" % (self.opensearch_api_url, self.index_pattern)
        f_url = "%s/%s/_refresh" % (self.opensearch_api_url, self.fake_index)
        self._make_query(url, self.index_pattern,
                         self.user_session.post, self.admin_session.post,
                         403, 200)
        self._make_query(f_url, self.fake_index, self.user_session.post,
                         self.admin_session.post, 403, 200)

    def test_run_flush(self):
        url = "%s/%s/_flush" % (self.opensearch_api_url, self.index_pattern)
        f_url = "%s/%s/_flush" % (self.opensearch_api_url, self.fake_index)
        self._make_query(url, self.index_pattern, self.user_session.post,
                         self.admin_session.post, 403, 200)
        self._make_query(f_url, self.fake_index, self.user_session.post,
                         self.admin_session.post, 403, 200)

    def test_run_forcemerge(self):
        url = "%s/%s/_forcemerge" % (self.opensearch_api_url,
                                     self.index_pattern)
        f_url = "%s/%s/_forcemerge" % (self.opensearch_api_url,
                                       self.fake_index)
        self._make_query(url, self.index_pattern, self.user_session.post,
                         self.admin_session.post, 403, 200)
        self._make_query(f_url, self.fake_index, self.user_session.post,
                         self.admin_session.post, 403, 200)

    def test_get_cluster_informations(self):
        index = None
        url = "%s/_nodes" % self.opensearch_api_url
        self._make_query(url, index, self.user_session.get,
                         self.admin_session.get, 403, 200)

        url = "%s/_nodes/_all" % self.opensearch_api_url
        self._make_query(url, index, self.user_session.get,
                         self.admin_session.get, 403, 200)

    def test_create_index_put_data(self):
        data = {
            'user': 'kimchey',
            'post_date': '2021-11-16T10:00:12',
            'message': 'some text'
        }
        headers = {'Content-type': 'application/json'}
        url = "%s/%s/_create/1" % (self.opensearch_api_url, self.index_pattern)
        f_url = "%s/%s/_create/1" % (self.opensearch_api_url, self.fake_index)
        self._make_query(url, self.index_pattern, self.user_session.put,
                         self.admin_session.put, 403, 201, data, headers)
        self._make_query(f_url, self.fake_index, self.user_session.put,
                         self.admin_session.put, 403, 201, data, headers)

    def test_read_data_from_index(self):
        url = "%s/%s/_create/1" % (self.opensearch_api_url, self.index_pattern)
        url_get = "%s/%s/_doc/1" % (self.opensearch_api_url,
                                    self.index_pattern)
        data = {
            'user': 'kimchy',
            'post_date': '2021-11-16T10:00:12',
            'message': 'some text'
        }
        headers = {'Content-type': 'application/json'}
        try:
            if not self._create_index(self.index_pattern):
                pytest.fail('Can not create index')
            r = self.admin_session.put(url, verify=self.insecure,
                                       headers=headers,
                                       data=json.dumps(data))
            assert r.status_code == 201
            # readonly user should be able to get content
            r = self.user_session.get(url_get, verify=self.insecure)
            response_source = json.loads(r.text)
            assert r.status_code == 200
            assert response_source['_source'] == data
        finally:
            self._delete_index(self.index_pattern)

    def test_read_data_from_fake_index(self):
        url = "%s/%s/_create/1" % (self.opensearch_api_url, self.fake_index)
        url_get = "%s/%s/_doc/1" % (self.opensearch_api_url,
                                    self.fake_index)
        data = {
            'user': 'kimchy',
            'post_date': '2021-11-16T10:00:12',
            'message': 'some text'
        }
        headers = {'Content-type': 'application/json'}
        try:
            if not self._create_index(self.fake_index):
                pytest.fail('Can not create index')
            r = self.admin_session.put(url, verify=self.insecure,
                                       headers=headers,
                                       data=json.dumps(data))
            assert r.status_code == 201
            # readonly user should be able to get content
            r = self.user_session.get(url_get, verify=self.insecure,
                                      headers=headers,
                                      data=json.dumps(data))
            assert r.status_code == 403
        finally:
            self._delete_index(self.fake_index)

    def test_update_data_from_index(self):
        url = "%s/%s/_create/1" % (self.opensearch_api_url, self.index_pattern)
        url_get = "%s/%s/_doc/1" % (self.opensearch_api_url,
                                    self.index_pattern)
        url_update = "%s/%s/_update/1" % (self.opensearch_api_url,
                                          self.index_pattern)
        data = {
            'user': 'kimchy',
            'post_date': '2021-11-16T10:00:12',
            'message': 'some text'
        }
        data_update = {"doc": {"user": "Timson"}}
        headers = {'Content-type': 'application/json'}
        try:
            if not self._create_index(self.index_pattern):
                pytest.fail('Can not create index')
            r = self.admin_session.put(url, verify=self.insecure,
                                       headers=headers,
                                       data=json.dumps(data))
            assert r.status_code == 201

            r = self.user_session.post(url_update, verify=self.insecure,
                                       headers=headers,
                                       data=json.dumps(data_update))
            assert r.status_code == 403

            r = self.admin_session.post(url_update, verify=self.insecure,
                                        headers=headers,
                                        data=json.dumps(data_update))
            assert r.status_code == 200

            # readonly user should read updated content
            r = self.user_session.get(url_get, verify=self.insecure)
            response_source = json.loads(r.text)
            assert r.status_code == 200
            assert response_source['_source']['user'] == 'Timson'
        finally:
            self._delete_index(self.index_pattern)
