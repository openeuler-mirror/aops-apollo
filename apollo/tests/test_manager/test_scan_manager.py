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
from unittest import mock

from vulcanus.restful.resp.state import SUCCEED

from apollo.conf import configuration
from apollo.database.proxy.task import TaskProxy, TaskMysqlProxy
from apollo.handler.task_handler.manager.scan_manager import ScanManager


class TestScanManager(unittest.TestCase):
    def setUp(self):
        proxy = TaskProxy(configuration)
        self.host_info = [
            {"host_name": "name1", "host_id": 1, "host_ip": "ip1"},
            {"host_name": "name2", "host_id": 2, "host_ip": "ip2"},
        ]
        self.manager = ScanManager('a', proxy, self.host_info, 'b')

    def tearDown(self):
        pass

    def test_pre_handle(self):
        with mock.patch.object(TaskMysqlProxy, 'update_host_scan') as mock_init_status:
            mock_init_status.return_value = 1
            res = self.manager.pre_handle()
            self.assertEqual(res, False)

        with mock.patch.object(TaskMysqlProxy, 'update_host_scan') as mock_init_status:
            mock_init_status.return_value = SUCCEED
            res = self.manager.pre_handle()
            self.assertEqual(res, True)
