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
from vulcanus.restful.response import BaseResponse

from apollo.conf.constant import VUL_HOST_SCAN
from apollo.handler.task_handler.view import VulScanHost
from apollo.tests import BaseTestCase


class TestHostScanView(BaseTestCase):
    client = BaseTestCase.create_app()
    headers = {"access_token": "123456"}

    @mock.patch.object(VulScanHost, '_handle')
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_handle):
        mock_verify_token.return_value = SUCCEED
        mock_handle.return_value = SUCCEED
        args = {
            "host_list": [1],
            "filter": {
                "host_name": "b",
                "host_group": [],
            },
        }
        response = self.client.post(VUL_HOST_SCAN, json=args, headers=self.headers)
        res = response.json
        expected_res = make_response(SUCCEED)
        self.assertDictEqual(res, expected_res)

        args = {"host_list": [1], "filter": {"host_name": 111, "host_group": [], "bb": 1}}
        response = self.client.post(VUL_HOST_SCAN, json=args, headers=self.headers)
        res = response.json
        expected_res = make_response(PARAM_ERROR)
        self.assertDictEqual(res, expected_res)

    def test_param_verify(self):
        interface = VulScanHost()
        host_list = []
        actual_host_list = []
        res = interface._verify_param(host_list, actual_host_list)
        self.assertEqual(res, False)

        actual_host_list = [{"host_id": 1, "status": "aa"}]
        res = interface._verify_param(host_list, actual_host_list)
        self.assertEqual(res, True)

        host_list = [1, 2]
        actual_host_list = [{"host_id": 2, "status": "b"}]
        res = interface._verify_param(host_list, actual_host_list)
        self.assertEqual(res, False)
