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

from vulcanus.restful.resp import make_response
from vulcanus.restful.resp.state import SUCCEED, PARAM_ERROR
from vulcanus.restful.response import BaseResponse
from vulcanus.manage import init_application

from apollo.database.proxy.task.base import TaskMysqlProxy, TaskProxy
from apollo.conf.constant import (
    VUL_TASK_CVE_FIX_INFO_GET,
    VUL_TASK_CVE_FIX_RESULT_GET,
    VUL_TASK_HOTPATCH_REMOVE_STATUS_GET,
    VUL_TASK_INFO_GET,
    VUL_TASK_LIST_GET,
    VUL_TASK_PROGRESS_GET,
    VUL_TASK_REPO_INFO_GET,
    VUL_TASK_REPO_RESULT_GET,
)
from apollo.conf import configuration
from apollo.url import URLS

app = init_application(name="apollo", settings=configuration, register_urls=URLS)

app.testing = True
client = app.test_client()
headers = {"access_token": "123456"}

succeed_response = make_response(SUCCEED)
param_error_response = make_response(PARAM_ERROR)


class TestGetTaskListView(unittest.TestCase):
    @mock.patch.object(TaskMysqlProxy, "get_task_list")
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_get_task_list):
        mock_verify_token.return_value = SUCCEED
        args = {"filter": {"task_name": "a", "task_type": ["cve fix"]}}

        mock_get_task_list.return_value = SUCCEED, {}
        res = client.post(VUL_TASK_LIST_GET, json=args, headers=headers).json
        self.assertDictEqual(res, succeed_response)

        args = {"filter": {"task_name": "a", "task_type": ["b"]}}
        res = client.post(VUL_TASK_LIST_GET, json=args, headers=headers).json
        self.assertDictEqual(res, param_error_response)


class TestGetTaskProgressView(unittest.TestCase):
    @mock.patch.object(TaskMysqlProxy, "get_task_progress")
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_get_task_progress):
        mock_verify_token.return_value = SUCCEED
        args = {"task_list": ["1"]}
        mock_get_task_progress.return_value = SUCCEED, {}
        res = client.post(VUL_TASK_PROGRESS_GET, json=args, headers=headers).json
        self.assertEqual(res, succeed_response)

        args = {"task_list": "b"}
        res = client.post(VUL_TASK_PROGRESS_GET, json=args, headers=headers).json
        self.assertEqual(res, param_error_response)


class TestGetTaskInfoView(unittest.TestCase):
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token):
        mock_verify_token.return_value = SUCCEED
        args = {"task_list": "b"}
        res = client.get(VUL_TASK_INFO_GET, data=args, headers=headers).json
        self.assertEqual(res, param_error_response)


class TestGetCveTaskInfoView(unittest.TestCase):
    @mock.patch.object(TaskMysqlProxy, "get_cve_task_info")
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_get_task_cve_status):
        mock_verify_token.return_value = SUCCEED
        args = {"task_id": "s", "page": 1, "per_page": 10, "filter": {"status": ["succeed"]}}
        mock_get_task_cve_status.return_value = SUCCEED, {}
        res = client.post(VUL_TASK_CVE_FIX_INFO_GET, json=args, headers=headers).json
        self.assertEqual(res, succeed_response)

        args = {"task_id": "s", "b": 1, "filter": {"status": ["succeed"]}}
        res = client.post(VUL_TASK_CVE_FIX_INFO_GET, json=args, headers=headers).json
        self.assertEqual(res, param_error_response)


class TestGetCveTaskStatusView(unittest.TestCase):
    @mock.patch.object(TaskMysqlProxy, "get_task_cve_status")
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_get_task_cve_status):
        mock_verify_token.return_value = SUCCEED
        args = {"task_id": "s", "cve_list": ["1", "2"]}
        mock_get_task_cve_status.return_value = SUCCEED, {}
        res = client.post(VUL_TASK_HOTPATCH_REMOVE_STATUS_GET, json=args, headers=headers).json
        self.assertEqual(res, succeed_response)

        args = {"task_id": "s", "cve_list": [1, 2]}
        res = client.post(VUL_TASK_HOTPATCH_REMOVE_STATUS_GET, json=args, headers=headers).json
        self.assertEqual(res, param_error_response)


class TestGetCveTaskResultView(unittest.TestCase):
    @mock.patch.object(TaskProxy, "get_task_cve_result")
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_get_task_cve_result):
        mock_verify_token.return_value = SUCCEED
        args = {"task_id": "s", "cve_list": ["1", "2"]}
        mock_get_task_cve_result.return_value = SUCCEED, {}
        res = client.post(VUL_TASK_CVE_FIX_RESULT_GET, json=args, headers=headers).json
        self.assertEqual(res, succeed_response)

        args = {"task_id": "s", "cve_list": [1, 2]}
        res = client.post(VUL_TASK_CVE_FIX_RESULT_GET, json=args, headers=headers).json
        self.assertEqual(res, param_error_response)


class TestGetRepoTaskInfoView(unittest.TestCase):
    @mock.patch.object(TaskMysqlProxy, "get_repo_task_info")
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_get_repo_task_info):
        mock_verify_token.return_value = SUCCEED
        args = {"task_id": "s", "filter": {"host_name": "n", "status": ["succeed", "fail"]}}
        mock_get_repo_task_info.return_value = SUCCEED, {}
        res = client.post(VUL_TASK_REPO_INFO_GET, json=args, headers=headers).json
        self.assertEqual(res, succeed_response)

        args = {"task_id": "s", "filter": {"host_name": "n", "status": ["succeed", "b"]}}
        res = client.post(VUL_TASK_REPO_INFO_GET, json=args, headers=headers).json
        self.assertEqual(res, param_error_response)


class TestGetRepoTaskResultView(unittest.TestCase):
    @mock.patch.object(TaskProxy, "get_task_repo_result")
    @mock.patch.object(BaseResponse, 'verify_token')
    @mock.patch.object(TaskProxy, '_create_session')
    def test_schema(self, mock_create_session, mock_verify_token, mock_get_task_repo_result):
        mock_create_session.return_value = None
        mock_verify_token.return_value = SUCCEED
        args = {"task_id": "s", "host_list": [1]}
        mock_get_task_repo_result.return_value = SUCCEED, {}
        res = client.post(VUL_TASK_REPO_RESULT_GET, json=args, headers=headers).json
        self.assertEqual(res, succeed_response)

        args = {"task_id": "s", "host_list": {}}
        res = client.post(VUL_TASK_REPO_RESULT_GET, json=args, headers=headers).json
        self.assertEqual(res, param_error_response)
