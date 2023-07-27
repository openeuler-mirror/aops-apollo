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
from unittest import mock

from vulcanus.restful.resp import make_response
from vulcanus.restful.resp.state import PARAM_ERROR, SUCCEED

from apollo.conf.constant import VUL_TASK_REPO_GENERATE
from apollo.handler.task_handler.view import VulGenerateRepoTask
from apollo.tests import BaseTestCase


class TestGenerateRepoTaskView(BaseTestCase):

    client = BaseTestCase.create_app()
    headers = {"access_token": "123456"}


    @mock.patch.object(VulGenerateRepoTask, '_handle')
    @mock.patch.object(VulGenerateRepoTask, 'verify_token')
    def test_schema(self, mock_verify_token, mock_handle):
        mock_verify_token.return_value = SUCCEED
        mock_handle.return_value = SUCCEED, {"task_id": "4"}
        args = {
            "task_name": "a",
            "description": "1",
            "repo_name": "r",
            "info": [{"host_id": 1, "host_name": "name1", "host_ip": "1.1.1.1"}],
        }
        response = self.client.post(VUL_TASK_REPO_GENERATE, json=args, headers=self.headers)
        res = response.json
        expected_res = make_response(SUCCEED)
        expected_res['data'] = {"task_id":"4"}
        self.assertDictEqual(res, expected_res)

        args = {
            "task_name": "a",
            "description": "1",
            "repo_name": "r",
            "info": [{"host_name": "name1", "host_ip": "1.1.1.1"}],
        }
        response = self.client.post(VUL_TASK_REPO_GENERATE, json=args, headers=self.headers)
        res = response.json
        expected_res = make_response(PARAM_ERROR)
        self.assertDictEqual(res, expected_res)
