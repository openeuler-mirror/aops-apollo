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

from collections import OrderedDict
from unittest import mock
from unittest.mock import Mock

from vulcanus.conf.constant import URL_FORMAT
from vulcanus.restful.resp.state import SUCCEED, PARAM_ERROR, SERVER_ERROR, TASK_EXECUTION_FAIL
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration
from apollo.conf.constant import VUL_TASK_CVE_FIX_CALLBACK, EXECUTE_CVE_FIX
from apollo.database.proxy.task.base import TaskProxy
from apollo.handler.task_handler.cache import TASK_CACHE
from apollo.handler.task_handler.manager.cve_fix_manager import CveFixManager
from apollo.tests import BaseTestCase


class CveFixManagerTestCase(BaseTestCase):
    def tearDown(self) -> None:
        super().setUp()
        TASK_CACHE.queue = OrderedDict()

    def test_create_task_should_return_succeed_directly_when_task_is_in_cache(self):
        fake_task = Mock()
        TASK_CACHE.put("id1", fake_task)
        manager = CveFixManager(Mock(), "id1")
        self.assertEqual(manager.create_task(), SUCCEED)
        self.assertEqual(manager.task, fake_task)

    def test_create_task_should_return_param_error_when_proxy_is_none(self):
        manager = CveFixManager(None, "id1")
        self.assertEqual(manager.create_task(), PARAM_ERROR)

    @mock.patch.object(TaskProxy, 'get_cve_basic_info')
    def test_create_task_should_return_no_succeed_when_query_from_database_fail(self, mock_proxy):
        proxy = TaskProxy()
        manager = CveFixManager(proxy, "id1")
        mock_proxy.return_value = (SERVER_ERROR, Mock())
        self.assertEqual(manager.create_task(), SERVER_ERROR)

    @mock.patch.object(TaskProxy, 'get_cve_basic_info')
    def test_create_task_should_return_succeed_and_query_from_db_when_task_in_db(self, mock_proxy):
        proxy = TaskProxy()
        manager = CveFixManager(proxy, "id1")
        fake_task = {"mock": Mock()}
        mock_proxy.return_value = (SUCCEED, fake_task)
        self.assertEqual(manager.create_task(), SUCCEED)
        fake_task["callback"] = VUL_TASK_CVE_FIX_CALLBACK
        self.assertEqual(manager.task, fake_task)

    @mock.patch.object(TaskProxy, 'init_cve_task')
    def test_pre_handle_should_return_false_when_init_task_fail(self, mock_init_status):
        proxy = TaskProxy()
        manager = CveFixManager(proxy, Mock())
        mock_init_status.return_value = Mock()
        self.assertFalse(manager.pre_handle())

    @mock.patch.object(TaskProxy, 'update_task_execute_time')
    @mock.patch.object(TaskProxy, 'init_cve_task')
    def test_pre_handle_should_return_true_when_init_task_succeed(self, mock_init_status, mock_update_time):
        proxy = TaskProxy()
        manager = CveFixManager(proxy, Mock())
        mock_init_status.return_value = SUCCEED
        mock_update_time.return_value = SUCCEED
        self.assertTrue(manager.pre_handle())

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
        mock_response.return_value = {"lebel": Mock()}
        manager.handle()
        mock_response.assert_called_with("POST", manager_url, fake_task, header)
        self.assertEqual(manager.result, None)

    @mock.patch.object(BaseResponse, 'get_response')
    def test_handle_should_succeed_with_task_when_response_succeed(self, mock_response):
        manager = CveFixManager(Mock(), Mock())
        fake_result = Mock()
        mock_response.return_value = {"label": SUCCEED, "data": {"result": {"task_result": fake_result}}}
        self.assertEqual(manager.handle(), SUCCEED)

    @mock.patch.object(TaskProxy, 'init_cve_task')
    @mock.patch.object(BaseResponse, 'get_response')
    def test_handle_should_error_when_response_failed(self, mock_response, mock_init_cve_task):
        manager = CveFixManager(Mock(), Mock())
        fake_result = Mock()
        mock_init_cve_task.return_value = SUCCEED
        mock_response.return_value = {"label": SERVER_ERROR, "data": {"result": {"task_result": fake_result}}}
        self.assertEqual(manager.handle(), TASK_EXECUTION_FAIL)
