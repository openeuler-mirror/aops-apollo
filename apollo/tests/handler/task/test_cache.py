#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
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

from apollo.handler.task_handler.cache import TaskCache


class TestCache(unittest.TestCase):
    def test_make_cve_info(self):
        cache = TaskCache(10)
        info = [
            {
                "cve_id": "1",
                "host_info": [
                    {"host_name": "name1", "host_id": 1, "host_ip": "ip1"},
                    {"host_name": "name2", "host_id": 2, "host_ip": "ip2"},
                ],
            },
            {"cve_id": "2", "host_info": [{"host_name": "name1", "host_id": 1, "host_ip": "ip1"}]},
        ]
        expected_res = {
            "cve": {"1": 1, "2": 1},
            "host": {
                "name1": {"host_name": "name1", "host_id": 1, "host_ip": "ip1", "cve": {"1": 1, "2": 1}},
                "name2": {"host_name": "name2", "host_id": 2, "host_ip": "ip2", "cve": {"1": 1}},
            },
        }
        res = cache.make_cve_info(info)
        self.assertDictEqual(res, expected_res)

    def test_query_repo_info(self):
        cache = TaskCache(10)
        info = {
            "result": [
                {"host_name": "name1", "host_id": 1, "host_ip": "ip1"},
                {"host_name": "name2", "host_id": 2, "host_ip": "ip2"},
            ]
        }
        expected_res = {
            "name1": {"host_name": "name1", "host_id": 1, "host_ip": "ip1"},
            "name2": {"host_name": "name2", "host_id": 2, "host_ip": "ip2"},
        }
        res = cache.query_repo_info('a', info)
        self.assertDictEqual(res, expected_res)
