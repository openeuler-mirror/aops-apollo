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
import time
import unittest
import uuid
from unittest import mock
from unittest.mock import Mock

from vulcanus.restful.resp.state import (
    DATABASE_CONNECT_ERROR,
    PARAM_ERROR,
    SUCCEED,
    UNKNOWN_ERROR,
    REPEAT_TASK_EXECUTION,
    DATABASE_UPDATE_ERROR,
)
from vulcanus.exceptions import DatabaseConnectionFailed

from apollo.conf.constant import *
from apollo.database.proxy.task.base import TaskProxy
from apollo.handler.task_handler.manager.cve_fix_manager import CveFixManager
from apollo.handler.task_handler.view import VulGenerateCveTask, VulExecuteTask
from apollo.tests import BaseTestCase

client = BaseTestCase.create_app()
header = {"Content-Type": "application/json; charset=UTF-8"}
header_with_token = {"Content-Type": "application/json; charset=UTF-8", "access_token": "81fe"}


class VulGenerteCveTaskTestCase(BaseTestCase):
    def test_handle_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_TASK_CVE_FIX_GENERATE, json=args).json
        self.assertEqual(response.get("message"), 'The method is not allowed for the requested URL.')

    def test_handle_should_return_param_error_when_input_wrong_param(self):
        args = {
            "task_name": "a",
            "description": "1",
            "info": [
                {
                    "cve_id": 1,
                    "host_info": [{"host_id": "id1", "host_name": "name1", "host_ip": "1.1.1.1"}],
                    "reboot": False,
                }
            ],
        }
        response = client.post(VUL_TASK_CVE_FIX_GENERATE, json=args, headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(TaskProxy, '_create_session')
    @mock.patch.object(VulGenerateCveTask, 'verify_request')
    def test_handle_should_return_database_connect_error_when_database_is_wrong(
        self, mock_verify_request, mock_connect
    ):
        mock_args = {
            "task_name": "cve fix",
            "description": "fix",
            "accepted": False,
            "info": [
                {
                    "cve_id": "CVE-2022-3736",
                    "host_info": [{"hotpatch": True, "host_id": 4, "host_name": "host1", "host_ip": "127.0.0.1"}],
                }
            ],
        }
        mock_verify_request.return_value = mock_args, SUCCEED
        mock_connect.side_effect = DatabaseConnectionFailed
        response = client.post(VUL_TASK_CVE_FIX_GENERATE, json={}, headers=header_with_token).json
        self.assertEqual(response['label'], DATABASE_CONNECT_ERROR)

    @mock.patch.object(uuid, 'uuid1')
    @mock.patch.object(time, 'time')
    @mock.patch.object(TaskProxy, 'validate_cves')
    @mock.patch.object(TaskProxy, 'validate_hosts')
    @mock.patch.object(TaskProxy, 'generate_cve_task')
    @mock.patch.object(TaskProxy, 'connect')
    @mock.patch.object(VulGenerateCveTask, 'verify_request')
    def test_handle_should_return_error_when_generate_fail(
        self,
        mock_verify_request,
        mock_connect,
        mock_generate_task,
        mock_validate_hosts,
        mock_validate_cves,
        mock_time,
        mock_uuid,
    ):
        mock_args = {
            "task_name": "cve fix",
            "description": "fix",
            "accepted": False,
            "info": [
                {
                    "cve_id": "CVE-2022-3736",
                    "host_info": [{"hotpatch": True, "host_id": 4, "host_name": "host1", "host_ip": "127.0.0.1"}],
                }
            ],
        }
        mock_verify_request.return_value = mock_args, SUCCEED
        mock_connect.return_value = True
        mock_time.return_value = 11
        mock_uuid.return_value = "aa"
        mock_validate_hosts.return_value = True
        mock_validate_cves.return_value = True
        mock_generate_task.return_value = UNKNOWN_ERROR
        response = client.post(VUL_TASK_CVE_FIX_GENERATE, json={}, headers=header_with_token).json
        mock_args.update({"task_id": "aa", "task_type": "cve fix", "create_time": 11})
        mock_generate_task.assert_called_with(mock_args)
        self.assertEqual(response['label'], UNKNOWN_ERROR)

    @mock.patch.object(uuid, 'uuid1')
    @mock.patch.object(time, 'time')
    @mock.patch.object(TaskProxy, 'validate_cves')
    @mock.patch.object(TaskProxy, 'validate_hosts')
    @mock.patch.object(TaskProxy, 'generate_cve_task')
    @mock.patch.object(TaskProxy, '_create_session')
    @mock.patch.object(VulGenerateCveTask, 'verify_token')
    def test_handle_should_return_task_id_when_generate_succeed(
        self,
        mock_verify_request,
        mock_connect,
        mock_generate_task,
        mock_validate_hosts,
        mock_validate_cves,
        mock_time,
        mock_uuid,
    ):
        mock_args = {
            "task_name": "cve fix",
            "description": "fix",
            "accepted": False,
            "info": [
                {
                    "cve_id": "CVE-2022-3736",
                    "host_info": [{"hotpatch": True, "host_id": 4, "host_name": "host1", "host_ip": "127.0.0.1"}],
                }
            ],
        }
        mock_verify_request.return_value = SUCCEED
        mock_connect.return_value = None
        mock_time.return_value = 11
        mock_uuid.return_value = "aa"
        mock_validate_hosts.return_value = True
        mock_validate_cves.return_value = True
        mock_generate_task.return_value = SUCCEED
        response = client.post(VUL_TASK_CVE_FIX_GENERATE, json=mock_args, headers=header_with_token).json
        mock_args.update({"task_id": "aa", "task_type": "cve fix", "create_time": 11})
        mock_generate_task.assert_called_with(mock_args)
        self.assertEqual(response['label'], SUCCEED)
        self.assertEqual(response.get("data", dict())['task_id'], "aa")


class VulExecuteTaskTestCase(unittest.TestCase):
    def test_handle_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_TASk_EXECUTE, json=args).json
        self.assertEqual(response.get("message"), 'The method is not allowed for the requested URL.')

    def test_handle_should_return_param_error_when_input_wrong_param(self):
        args = {"task_id": 2}
        response = client.post(VUL_TASk_EXECUTE, json=args, headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(TaskProxy, '_create_session')
    @mock.patch.object(VulExecuteTask, 'verify_request')
    def test_handle_should_return_connect_error_when_database_error(self, mock_verify_request, mock_connect):
        mock_verify_request.return_value = {}, SUCCEED
        mock_connect.side_effect = DatabaseConnectionFailed
        response = client.post(VUL_TASk_EXECUTE, json={}, headers=header_with_token).json
        self.assertEqual(response['label'], DATABASE_CONNECT_ERROR)

    @mock.patch.object(TaskProxy, 'get_task_type')
    @mock.patch.object(TaskProxy, 'connect')
    @mock.patch.object(VulExecuteTask, 'verify_request')
    def test_handle_should_return_param_error_when_task_type_error(
        self, mock_verify_request, mock_connect, mock_get_task_type
    ):
        fake_task_id = Mock()
        fake_username = Mock()
        mock_verify_request.return_value = {"task_id": fake_task_id, "username": fake_username}, SUCCEED
        mock_connect.return_value = True
        mock_get_task_type.return_value = Mock()
        response = client.post(VUL_TASk_EXECUTE, json={}, headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(TaskProxy, 'check_task_status')
    @mock.patch.object(TaskProxy, 'get_task_type')
    @mock.patch.object(TaskProxy, 'connect')
    @mock.patch.object(VulExecuteTask, 'verify_request')
    def test_handle_should_return_repeat_error_when_task_repeat_execute(
        self, mock_verify_request, mock_connect, mock_get_task_type, mock_check_task_status
    ):
        fake_task_id = Mock()
        fake_username = Mock()
        mock_verify_request.return_value = {"task_id": fake_task_id, "username": fake_username}, SUCCEED
        mock_connect.return_value = True
        mock_get_task_type.return_value = "cve fix"
        mock_check_task_status.return_value = False
        response = client.post(VUL_TASk_EXECUTE, json={}, headers=header_with_token).json
        self.assertEqual(response['label'], REPEAT_TASK_EXECUTION)

    @mock.patch.object(CveFixManager, 'create_task')
    def test_handle_cve_fix_should_return_error_when_create_task_fail(self, mock_create_task):
        mock_create_task.return_value = UNKNOWN_ERROR
        args = {"task_id": Mock(), "token": Mock()}
        res = VulExecuteTask._handle_cve_fix(args, Mock())
        self.assertEqual(res, UNKNOWN_ERROR)

    @mock.patch.object(CveFixManager, 'pre_handle')
    @mock.patch.object(CveFixManager, 'create_task')
    def test_handle_cve_fix_should_return_update_error_when_pre_handle_fail(self, mock_create_task, mock_pre_handle):
        mock_create_task.return_value = SUCCEED
        mock_pre_handle.return_value = False
        args = {"task_id": Mock(), "token": Mock()}
        res = VulExecuteTask._handle_cve_fix(args, Mock())
        self.assertEqual(res, DATABASE_UPDATE_ERROR)

    @mock.patch.object(CveFixManager, 'execute_task')
    @mock.patch.object(CveFixManager, 'pre_handle')
    @mock.patch.object(CveFixManager, 'create_task')
    def test_handle_cve_fix_should_return_succeed_when_all_is_right(
        self, mock_create_task, mock_pre_handle, mock_execute
    ):
        mock_create_task.return_value = SUCCEED
        mock_pre_handle.return_value = True
        args = {"task_id": Mock(), "token": Mock()}
        res = VulExecuteTask._handle_cve_fix(args, Mock())
        self.assertEqual(res, SUCCEED)


class VulCveFixTaskCallbackTestCase(unittest.TestCase):
    def test_handle_should_return_param_error_when_input_wrong_param(self):
        args = {"task_id": "", "host_id": "1", "cves": {"cve1": "fixed", "cve2": "x"}}
        response = client.post(VUL_TASK_CVE_FIX_CALLBACK, json=args, headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)
