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
from collections import OrderedDict
from unittest import mock
from unittest.mock import Mock

from vulcanus.conf.constant import URL_FORMAT, EXECUTE_CVE_FIX
from vulcanus.restful.resp.state import SUCCEED, PARAM_ERROR, SERVER_ERROR
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration
from apollo.conf.constant import VUL_TASK_CVE_FIX_CALLBACK, CveHostStatus
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.cache import TASK_CACHE
from apollo.handler.task_handler.manager.cve_fix_manager import CveFixManager


class CveFixManagerTestCase(unittest.TestCase):
    def tearDown(self) -> None:
        TASK_CACHE.queue = OrderedDict()

    def test_create_task_should_return_SUCCEED_directly_when_task_is_in_cache(self):
        fake_task = Mock()
        TASK_CACHE.put("id1", fake_task)
        manager = CveFixManager(Mock(), "id1")
        self.assertEqual(manager.create_task(), SUCCEED)
        self.assertEqual(manager.task, fake_task)

    def test_create_task_should_return_PARAM_ERROR_when_proxy_is_none(self):
        manager = CveFixManager(None, "id1")
        self.assertEqual(manager.create_task(), PARAM_ERROR)

    @mock.patch.object(TaskProxy, 'get_cve_basic_info')
    def test_create_task_should_return_no_SUCCEED_when_query_from_database_fail(self, mock_proxy):
        proxy = TaskProxy(configuration)
        manager = CveFixManager(proxy, "id1")
        mock_proxy.return_value = (SERVER_ERROR, Mock())
        self.assertEqual(manager.create_task(), SERVER_ERROR)

    @mock.patch.object(TaskProxy, 'get_cve_basic_info')
    def test_create_task_should_return_SUCCEED_and_query_from_db_when_task_in_db(self, mock_proxy):
        proxy = TaskProxy(configuration)
        manager = CveFixManager(proxy, "id1")
        fake_task = {"mock": Mock()}
        mock_proxy.return_value = (SUCCEED, fake_task)
        self.assertEqual(manager.create_task(), SUCCEED)
        fake_task["callback"] = VUL_TASK_CVE_FIX_CALLBACK
        self.assertEqual(manager.task, fake_task)

    @mock.patch.object(TaskProxy, 'init_cve_task')
    def test_pre_handle_should_return_False_when_init_task_fail(self, mock_init_status):
        proxy = TaskProxy(configuration)
        manager = CveFixManager(proxy, Mock())
        mock_init_status.return_value = Mock()
        self.assertEqual(manager.pre_handle(), False)

    @mock.patch.object(TaskProxy, 'update_task_execute_time')
    @mock.patch.object(TaskProxy, 'init_cve_task')
    def test_pre_handle_should_return_True_when_init_task_succeed(self, mock_init_status, mock_update_time):
        proxy = TaskProxy(configuration)
        manager = CveFixManager(proxy, Mock())
        mock_init_status.return_value = SUCCEED
        mock_update_time.return_value = SUCCEED
        self.assertEqual(manager.pre_handle(), True)

    @mock.patch.object(BaseResponse, 'get_response')
    def test_handle_should_assign_result_with_empty_when_response_fail(self, mock_response):
        fake_task = Mock()
        fake_task_id = Mock()
        fake_token = Mock()
        manager_url = URL_FORMAT % (configuration.zeus.get('IP'), configuration.zeus.get('PORT'), EXECUTE_CVE_FIX)
        header = {"access_token": fake_token, "Content-Type": "application/json; charset=UTF-8"}
        manager = CveFixManager(Mock(), fake_task_id)
        manager.task = fake_task
        manager.token = fake_token
        mock_response.return_value = {"code": Mock()}
        manager.handle()
        mock_response.assert_called_with("POST", manager_url, fake_task, header)
        self.assertEqual(manager.result, [])

    @mock.patch.object(BaseResponse, 'get_response')
    def test_handle_should_assign_result_with_task_when_response_succeed(self, mock_response):
        manager = CveFixManager(Mock(), Mock())
        fake_result = Mock()
        mock_response.return_value = {"code": SUCCEED, "result": {"task_result": fake_result}}
        manager.handle()
        self.assertEqual(manager.result, fake_result)

    @mock.patch.object(CveFixManager, '_save_result')
    @mock.patch.object(CveFixManager, 'fault_handle')
    def test_post_handle_should_be_correct(self, mock_fault_handle, mock_save_result):
        manager = CveFixManager(Mock(), Mock())
        fake_result = [
            {
                "host_id": 1,
                "check_items": [{"item": "net", "result": False}],
                "cves": [{"cve_id": "cve1", "log": "", "result": CveHostStatus.SUCCEED}],
            },
            {
                "host_id": 2,
                "check_items": [],
                "cves": [
                    {"cve_id": "cve1", "log": "", "result": CveHostStatus.SUCCEED},
                    {"cve_id": "cve2", "log": "", "result": CveHostStatus.FAIL},
                ],
            },
            {
                "host_id": 2,
                "check_items": [{"item": "net", "result": True}],
                "cves": [
                    {"cve_id": "cve1", "log": "", "result": CveHostStatus.SUCCEED},
                    {"cve_id": "cve2", "log": "", "result": CveHostStatus.SUCCEED},
                ],
            },
        ]
        manager.result = fake_result
        manager.post_handle()
        fake_result[0]['status'] = "fail"
        fake_result[1]['status'] = "fail"
        fake_result[2]['status'] = "succeed"
        self.assertEqual(manager.result, fake_result)

    @mock.patch.object(TaskProxy, 'fix_task_status')
    @mock.patch.object(TaskProxy, 'set_cve_progress')
    def test_fault_handle_should_have_correct_step(self, mock_set_cve_progress, mock_fix_task_status):
        proxy = TaskProxy(configuration)
        fake_task_id = Mock()
        manager = CveFixManager(proxy, fake_task_id)
        manager.fault_handle()
        mock_set_cve_progress.assert_called_with(fake_task_id, [], 'fill')
        mock_fix_task_status.assert_called_with(fake_task_id, 'cve fix')
