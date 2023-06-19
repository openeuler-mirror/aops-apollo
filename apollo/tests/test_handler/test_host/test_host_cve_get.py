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
Time: 2023/06/16
Author:
Description: 
"""
import json
from unittest import mock

import sqlalchemy
from vulcanus.restful.resp import state
from vulcanus.restful.response import BaseResponse

from apollo.conf.constant import VUL_HOST_CVE_GET
from apollo.database.proxy.host import HostProxy
from apollo.tests import BaseTestCase


class TestHostCveGet(BaseTestCase):
    client = BaseTestCase.create_app()

    def setUp(self) -> None:
        self.header = {
            "Content-Type": "application/json; charset=UTF-8"
        }
        self.mock_args = {
            "host_id": 1
        }
        self.mock_host_cve_info = {
            "total_count": 1,
            "total_page": 1,
            "result": [
                {
                    "cve_id": "id1",
                    "publish_time": "2020-09-24",
                    "severity": "high",
                    "description": "a long description",
                    "cvss_score": "7.2",
                    "hotpatch": True
                }
            ]
        }

    @mock.patch.object(HostProxy, "__exit__")
    @mock.patch.object(HostProxy, "get_host_cve")
    @mock.patch.object(HostProxy, "_create_session")
    @mock.patch.object(BaseResponse, "verify_token")
    def test_host_cve_get_should_return_cve_list_of_host_when_all_is_right(
            self, mock_verify_token, mock_connect, mock_host_cve_info, mock_close):
        mock_verify_token.return_value = state.SUCCEED
        mock_connect.return_value = None
        mock_host_cve_info.return_value = state.SUCCEED, self.mock_host_cve_info
        mock_close.return_value = None
        response = self.client.post(VUL_HOST_CVE_GET, data=json.dumps(self.mock_args), headers=self.header)
        self.assertEqual(state.SUCCEED, response.json.get("label"), response.json)

    @mock.patch.object(BaseResponse, "verify_token")
    def test_host_cve_get_should_return_token_error_when_request_with_incorrect_token_or_without_token(
            self, mock_verify_token):
        mock_verify_token.return_value = state.TOKEN_ERROR
        response = self.client.post(VUL_HOST_CVE_GET, data=json.dumps(self.mock_args), headers=self.header)
        self.assertEqual(state.TOKEN_ERROR, response.json.get("label"), response.json)

    def test_host_cve_get_should_return_param_error_when_request_with_incorrect_args(self):
        response = self.client.post(VUL_HOST_CVE_GET, data=json.dumps({}), headers=self.header)
        self.assertEqual(state.PARAM_ERROR, response.json.get("label"), response.json)

    def test_host_cve_get_should_return_400_when_request_without_args(self):
        response = self.client.post(VUL_HOST_CVE_GET, headers=self.header)
        self.assertEqual(400, response.status_code)

    def test_host_cve_get_should_return_405_when_request_with_incorrect_method(self):
        response = self.client.put(VUL_HOST_CVE_GET, data=json.dumps(self.mock_args), headers=self.header)
        self.assertEqual(405, response.status_code)

    @mock.patch.object(HostProxy, "_create_session")
    @mock.patch.object(BaseResponse, "verify_token")
    def test_host_cve_get_should_return_database_connect_error_when_connect_database_failed(
            self, mock_token, mock_connect):
        mock_token.return_value = state.SUCCEED
        mock_connect.side_effect = sqlalchemy.exc.SQLAlchemyError("Connection error")
        response = self.client.post(VUL_HOST_CVE_GET, data=json.dumps(self.mock_args), headers=self.header)
        self.assertEqual(state.DATABASE_CONNECT_ERROR, response.json.get("label"), response.json)
