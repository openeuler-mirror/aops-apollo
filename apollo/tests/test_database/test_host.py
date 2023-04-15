#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
"""
Time:
Author:
Description:
"""
import unittest

from flask import g

from apollo.conf import configuration
from apollo.database.proxy.host import HostProxy
from apollo.tests.test_database.helper import setup_mysql_db, setup_es_db, tear_down_mysql_db, tear_down_es_db
from vulcanus.restful.resp.state import SUCCEED, PARTIAL_SUCCEED, NO_DATA


class TestHostDatabase(unittest.TestCase):
    host_database = HostProxy(configuration)
    host_database.connect()

    @classmethod
    def setUpClass(cls):
        setup_mysql_db()
        setup_es_db()

    @classmethod
    def tearDownClass(cls):
        tear_down_mysql_db()
        tear_down_es_db()

    def test_get_host_list_sort(self):
        data = {
            "sort": "cve_num",
            "direction": "desc",
            "page": 1,
            "per_page": 10,
            "username": "admin",
            "filter": {}
        }
        expected_query_result = {
            "total_count": 3,
            "total_page": 1,
            "result": [
                {
                    "host_id": 2, "host_name": "host2", "host_ip": "127.0.0.2",
                    "host_group": "group1", "repo": "repo1", "cve_num": 2, "last_scan": 123836152
                },
                {
                    "host_id": 1, "host_name": "host1", "host_ip": "127.0.0.1",
                    "host_group": "group1", "repo": "repo1", "cve_num": 1, "last_scan": 123836100
                },
                {'cve_num': 0,
                 'host_group': 'group1',
                 'host_id': 3,
                 'host_ip': '127.0.0.2',
                 'host_name': 'host3',
                 'last_scan': 123837152,
                 'repo': 'repo1'}
            ]
        }
        self.assertEqual(self.host_database.get_host_list(
            data), (SUCCEED, expected_query_result))

        data = {
            "sort": "cve_num",
            "direction": "asc",
            "page": 1,
            "per_page": 10,
            "username": "admin",
            "filter": {}
        }
        expected_query_result = {
            "total_count": 3,
            "total_page": 1,
            "result": [
                {'cve_num': 0,
                 'host_group': 'group1',
                 'host_id': 3,
                 'host_ip': '127.0.0.2',
                 'host_name': 'host3',
                 'last_scan': 123837152,
                 'repo': 'repo1'},
                {
                    "host_id": 1, "host_name": "host1", "host_ip": "127.0.0.1",
                    "host_group": "group1", "repo": "repo1", "cve_num": 1, "last_scan": 123836100
                },
                {
                    "host_id": 2, "host_name": "host2", "host_ip": "127.0.0.2",
                    "host_group": "group1", "repo": "repo1", "cve_num": 2, "last_scan": 123836152
                }
            ]
        }
        self.assertEqual(self.host_database.get_host_list(
            data), (SUCCEED, expected_query_result))

    def test_get_host_list_filter(self):
        data = {
            "sort": "",
            "direction": "",
            "page": 1,
            "per_page": 10,
            "username": "admin",
            "filter": {"host_name": "host1"}
        }
        expected_query_result = {
            "total_count": 1,
            "total_page": 1,
            "result": [
                {
                    "host_id": 1, "host_name": "host1", "host_ip": "127.0.0.1",
                    "host_group": "group1", "repo": "repo1", "cve_num": 1, "last_scan": 123836100
                }
            ]
        }
        self.assertEqual(self.host_database.get_host_list(
            data), (SUCCEED, expected_query_result))

    def test_get_host_status(self):
        # get exist hosts
        data = {
            "username": "admin",
            "host_list": [1, 2]
        }
        expected_query_result = {
            "result": {1: "done", 2: "scanning"}
        }
        self.assertEqual(self.host_database.get_hosts_status(
            data), (SUCCEED, expected_query_result))

        # get partial exist hosts
        data = {
            "username": "admin",
            "host_list": [1, 4]
        }
        expected_query_result = {
            "result": {1: "done"}
        }
        self.assertEqual(self.host_database.get_hosts_status(
            data), (PARTIAL_SUCCEED, expected_query_result))

        # get not exist hosts
        data = {
            "username": "admin",
            "host_list": [4, 5]
        }
        self.assertEqual(self.host_database.get_hosts_status(
            data), (NO_DATA, {"result": {}}))

        # get all hosts
        data = {
            "username": "admin",
            "host_list": []
        }
        expected_query_result = {
            "result": {1: "done", 2: "scanning", 3: "scanning"}
        }
        self.assertEqual(self.host_database.get_hosts_status(
            data), (SUCCEED, expected_query_result))

    def test_get_host_info(self):
        # get exist host info
        data = {
            "username": "admin",
            "host_id": 1
        }
        expected_query_result = {
            "result": {'affected_cve_num': 1,
                       'host_group': 'group1',
                       'host_ip': '127.0.0.1',
                       'host_name': 'host1',
                       'last_scan': 123836100,
                       'repo': 'repo1',
                       'unaffected_cve_num': 1}
        }
        self.assertEqual(self.host_database.get_host_info(
            data), (SUCCEED, expected_query_result))

        # get not exist host info
        data = {
            "username": "admin",
            "host_id": 0
        }
        self.assertEqual(self.host_database.get_host_info(
            data), (NO_DATA, {"result": {}}))

    def test_get_host_cve(self):
        # query exist host
        data = {"host_id": 1, "username": "admin"}
        expected_query_result = {
            "total_count": 2, "total_page": 1,
            "result": [
                {
                    "cve_id": "qwfqwff3",
                    "publish_time": "qwff",
                    "severity": "High",
                    "description": "asdqwfqwf",
                    "cvss_score": "7.2",
                    "status": "in review"
                },
                {
                    "cve_id": "qwfqwff4",
                    "publish_time": "asyubdqsd",
                    "severity": "Medium",
                    "description": "sef",
                    "cvss_score": "3",
                    "status": "not reviewed"
                }
            ]
        }
        self.assertEqual(self.host_database.get_host_cve(
            data), (SUCCEED, expected_query_result))

        # query filtered host cve
        data = {
            "host_id": 1,
            "username": "admin",
            "filter": {
                "cve_id": "ff3"
            }
        }
        expected_query_result = {
            "total_count": 1, "total_page": 1,
            "result": [
                {
                    "cve_id": "qwfqwff3",
                    "publish_time": "qwff",
                    "severity": "High",
                    "description": "asdqwfqwf",
                    "cvss_score": "7.2",
                    "status": "in review"
                }
            ]
        }
        self.assertEqual(self.host_database.get_host_cve(
            data), (SUCCEED, expected_query_result))

        # query not exist host
        data = {"host_id": 0, "username": "admin"}
        expected_query_result = {
            "total_count": 0, "total_page": 1, "result": []}
        self.assertEqual(self.host_database.get_host_cve(
            data), (SUCCEED, expected_query_result))
