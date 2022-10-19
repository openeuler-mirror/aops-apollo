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
import os
import unittest
from unittest import mock
from collections import namedtuple

from apollo.handler.task_handler.manager.scan_manager import ScanManager
from apollo.handler.task_handler.manager.task_manager import CveAnsible
from apollo.handler.task_handler.config import PLAYBOOK_DIR
from apollo.conf import configuration
from apollo.database.proxy.task import TaskProxy
from apollo.conf.constant import ANSIBLE_TASK_STATUS

from vulcanus.restful.status import SUCCEED

class TestScanManager(unittest.TestCase):
    def setUp(self):
        proxy = TaskProxy(configuration)
        self.host_info = [
            {
                "host_name": "name1",
                "host_id": "id1",
                "host_ip": "ip1"
            },
            {
                "host_name": "name2",
                "host_id": "id2",
                "host_ip": "ip2"
            }
        ]
        self.manager = ScanManager('a', proxy, self.host_info, 'b')

    def tearDown(self):
        pass

    def test_pre_handle(self):
        with mock.patch.object(TaskProxy, 'init_host_scan') as mock_init_status:
            mock_init_status.return_value = 1
            res = self.manager.pre_handle()
            self.assertEqual(res, False)
        
        with mock.patch.object(TaskProxy, 'init_host_scan') as mock_init_status:
            mock_init_status.return_value = SUCCEED
            res = self.manager.pre_handle()
            self.assertEqual(res, True)
    
    def test_handle(self):
        path = os.path.join(PLAYBOOK_DIR, 'a' + '.yml')
        with mock.patch.object(CveAnsible, 'playbook') as mock_pb:
            mock_pb.return_value = True
            self.manager.handle()
            mock_pb.assert_called_with([path])

    @mock.patch.object(TaskProxy, 'update_scan_status')
    @mock.patch.object(TaskProxy, 'save_scan_result')
    def test_post_handle(self, mock_scan_result, mock_scan_status):
        task = namedtuple('task', ['result', 'info'])
        task.result = {
            "name1": {
                "scan": {
                    "status": ANSIBLE_TASK_STATUS.SUCCEED,
                    "info": "CVE-11-21 SADA \n CVE-2-1"
                }
            },
            "name2": {
                "scan": {
                    "status": ANSIBLE_TASK_STATUS.SUCCEED,
                    "info": "CVE"
                }
            }
        }
        task.info = {
                "name1": {
                    "host_id": "id1",
                    "host_name": "name1",
                    "host_ip": "ip1"
                },
                "name2": {
                    "host_id": "id2",
                    "host_name": "name2",
                    "host_ip": "ip2"
                }
        }
        expected_res = {
            "id1": ["CVE-11-21", "CVE-2-1"],
            "id2": []
        }
        
        self.manager.task = task
        self.manager.post_handle()
        mock_scan_status.assert_called_with(["id1", "id2"])
        mock_scan_result.assert_called_with('b', expected_res)
    