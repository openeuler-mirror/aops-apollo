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

import unittest
from unittest import mock
from unittest.mock import Mock

from apollo.conf import configuration
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.manager.scan_manager import ScanManager
from vulcanus.conf.constant import URL_FORMAT, EXECUTE_CVE_SCAN
from vulcanus.restful.response import BaseResponse
from vulcanus.restful.status import SUCCEED, PARAM_ERROR, SERVER_ERROR, DATABASE_UPDATE_ERROR


class CveScanManagerTestCase(unittest.TestCase):
    def test_create_task_should_return_PARAM_ERROR_when_proxy_is_none(self):
        host_info = Mock()
        manager = ScanManager("id1", None, host_info, "admin")
        self.assertEqual(manager.create_task(), PARAM_ERROR)

    @mock.patch.object(TaskProxy, 'get_scan_host_info')
    def test_create_task_should_return_no_SUCCEED_when_query_from_database_fail(
            self, mock_proxy):
        host_info = [
            {
                "host_id": "host_id1",
                "host_ip": "127.0.0.1",
                "host_name": "host_name1",
                "status": "0"
            }
        ]
        proxy = TaskProxy(configuration)
        manager = ScanManager("id1", proxy, host_info, "admin")
        mock_proxy.return_value = (SERVER_ERROR, Mock())
        self.assertEqual(manager.create_task(), SERVER_ERROR)

    @mock.patch.object(TaskProxy, 'get_scan_host_info')
    def test_create_task_should_return_SUCCEED_when_query_from_database_success(
            self, mock_proxy):
        host_info = Mock()
        proxy = TaskProxy(configuration)
        manager = ScanManager("id1", proxy, host_info, "admin")
        mock_proxy.return_value = (SUCCEED, Mock())
        self.assertEqual(manager.create_task(), SUCCEED)

    @mock.patch.object(TaskProxy, 'update_host_scan')
    def test_pre_handle_should_return_False_when_update_host_scan_fail(
            self, mock_update_host_scan):
        proxy = TaskProxy(configuration)
        host_info = Mock()
        manager = ScanManager("id1", proxy, host_info, "admin")
        mock_update_host_scan.return_value = (DATABASE_UPDATE_ERROR)
        self.assertEqual(manager.pre_handle(), False)

    @mock.patch.object(TaskProxy, 'update_host_scan')
    def test_pre_handle_should_return_True_when_update_host_scan_succeed(
            self, mock_update_host_scan):
        proxy = TaskProxy(configuration)
        host_info = Mock()
        manager = ScanManager("id1", proxy, host_info, "admin")
        mock_update_host_scan.return_value = SUCCEED
        self.assertEqual(manager.pre_handle(), True)

    @mock.patch.object(BaseResponse, 'get_response')
    def test_handle_should_assign_result_with_empty_when_response_fail(
            self, mock_response):
        fake_task = Mock()
        fake_token = Mock()
        manager_url = URL_FORMAT % (configuration.zeus.get('IP'),
                                    configuration.zeus.get('PORT'),
                                    EXECUTE_CVE_SCAN)
        header = {
            "access_token": fake_token,
            "Content-Type": "application/json; charset=UTF-8"
        }
        manager = ScanManager(Mock(), Mock(), Mock(), Mock())
        manager.task = fake_task
        manager.token = fake_token
        mock_response.return_value = {"code": Mock()}
        manager.handle()
        mock_response.assert_called_with(
            "POST", manager_url, fake_task, header)
        self.assertEqual(manager.result, [])

    @mock.patch.object(BaseResponse, 'get_response')
    def test_handle_should_assign_result_with_task_when_response_succeed(
            self, mock_response):
        manager = ScanManager(Mock(), Mock(), Mock(), Mock())
        fake_result = Mock()
        mock_response.return_value = {
            "code": SUCCEED, "result": {"task_result": fake_result}}
        manager.handle()
        self.assertEqual(manager.result, fake_result)

    def test_post_handle_should_be_correct(self):
        manager = ScanManager(Mock(), Mock(), Mock(), Mock())
        fake_result = [
            {
                "host_id": "host_id1",
                "host_ip": "127.0.0.1",
                "host_name": "host_name1",
                "log": "restful connection error",
            },
            {
                "host_id": "host_id2",
                "host_ip": "127.0.0.2",
                "host_name": "host_name2",
                "log": "scan finish",
            },
            {
                "host_id": "host_id3",
                "host_ip": "127.0.0.3",
                "host_name": "host_name3",
                "log": "no matching data found in the database",
            }
        ]
        manager.result = fake_result
        manager.post_handle()
        fake_result[0]['status'] = "fail"
        fake_result[1]['status'] = "succeed"
        fake_result[2]['status'] = "unknown"
        self.assertEqual(manager.result, fake_result)

    @mock.patch.object(TaskProxy, "update_host_scan")
    def test_fault_handle_should_have_correct_step(
            self, mock_update_host_scan):
        host_list = Mock()
        proxy = TaskProxy(configuration)
        manager = ScanManager(Mock(), proxy, host_list, Mock())
        manager.fault_handle()
        mock_update_host_scan.assert_called_with("finish", host_list)
