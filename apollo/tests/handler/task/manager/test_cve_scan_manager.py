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

from unittest import mock
from unittest.mock import Mock

from vulcanus.conf.constant import URL_FORMAT
from vulcanus.restful.resp.state import SUCCEED, DATABASE_UPDATE_ERROR
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration
from apollo.conf.constant import EXECUTE_CVE_SCAN
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.manager.scan_manager import ScanManager
from apollo.tests import BaseTestCase


class CveScanManagerTestCase(BaseTestCase):

    @mock.patch.object(TaskProxy, 'query_host_cve_info')
    def test_create_task_should_return_SUCCEED_when_query_from_database_success(self, mock_proxy):
        host_info = [{"host_id": 1, "host_ip": "127.0.0.1", "host_name": "host_name1", "status": "0"}]
        proxy = TaskProxy()
        manager = ScanManager("id1", proxy, host_info, "admin")
        mock_proxy.return_value = (SUCCEED, Mock())
        self.assertEqual(manager.create_task(), SUCCEED)

    @mock.patch.object(TaskProxy, 'update_host_scan')
    def test_pre_handle_should_return_False_when_update_host_scan_fail(self, mock_update_host_scan):
        proxy = TaskProxy()
        host_info = [{"host_id": 1, "host_ip": "127.0.0.1", "host_name": "host_name1", "status": "0"}]
        manager = ScanManager("id1", proxy, host_info, "admin")
        mock_update_host_scan.return_value = DATABASE_UPDATE_ERROR
        self.assertEqual(manager.pre_handle(), False)

    @mock.patch.object(TaskProxy, 'update_host_scan')
    def test_pre_handle_should_return_True_when_update_host_scan_succeed(self, mock_update_host_scan):
        proxy = TaskProxy()
        host_info = [{"host_id": 1, "host_ip": "127.0.0.1", "host_name": "host_name1", "status": "0"}]
        manager = ScanManager("id1", proxy, host_info, "admin")
        mock_update_host_scan.return_value = SUCCEED
        self.assertEqual(manager.pre_handle(), True)

    @mock.patch.object(BaseResponse, 'get_response')
    def test_handle_should_assign_result_with_empty_when_response_fail(self, mock_response):
        fake_task = Mock()
        fake_token = Mock()
        manager_url = URL_FORMAT % (configuration.zeus.get('IP'), configuration.zeus.get('PORT'), EXECUTE_CVE_SCAN)
        header = {"access_token": fake_token, "Content-Type": "application/json; charset=UTF-8"}
        host_info = [{"host_id": 1, "host_ip": "127.0.0.1", "host_name": "host_name1", "status": "0"}]
        manager = ScanManager(Mock(), Mock(), host_info, Mock())
        manager.task = fake_task
        manager.token = fake_token
        mock_response.return_value = {"code": Mock()}
        manager.handle()
        mock_response.assert_called_with("POST", manager_url, fake_task, header)
        self.assertEqual(manager.result, None)

    @mock.patch.object(BaseResponse, 'get_response')
    def test_handle_should_assign_result_with_task_when_response_succeed(self, mock_response):
        host_info = [{"host_id": 1, "host_ip": "127.0.0.1", "host_name": "host_name1", "status": "0"}]
        manager = ScanManager(Mock(), Mock(), host_info, Mock())
        fake_result = Mock()
        mock_response.return_value = {
            "code": "200",
            "data": {
                "task_result": fake_result
            },
            "label": "Succeed",
            "message": "operation succeed"
        }
        manager.handle()
        self.assertEqual(manager.result, fake_result)

    def test_post_handle_should_be_correct(self):
        host_info = [{"host_id": 1, "host_ip": "127.0.0.1", "host_name": "host_name1", "status": "0"}]
        manager = ScanManager(Mock(), Mock(), host_info, Mock())
        fake_result = [
            {
                "host_id": 1,
                "host_ip": "127.0.0.1",
                "host_name": "host_name1",
                "log": "restful connection error",
            },
            {
                "host_id": 2,
                "host_ip": "127.0.0.2",
                "host_name": "host_name2",
                "log": "scan finish",
            },
            {
                "host_id": 3,
                "host_ip": "127.0.0.3",
                "host_name": "host_name3",
                "log": "no matching data found in the database",
            },
        ]
        manager.result = fake_result
        manager.post_handle()
        fake_result[0]['status'] = "fail"
        fake_result[1]['status'] = "succeed"
        fake_result[2]['status'] = "unknown"
        self.assertEqual(manager.result, fake_result)

    @mock.patch.object(TaskProxy, "update_host_scan")
    def test_fault_handle_should_have_correct_step(self, mock_update_host_scan):
        host_list = [{"host_id": 1}]
        proxy = TaskProxy()
        manager = ScanManager(Mock(), proxy, host_list, Mock())
        manager.fault_handle()
        mock_update_host_scan.assert_called_with("finish", [1])
