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
import shutil
import unittest
from unittest import mock

from flask import Flask, Blueprint
from flask_restful import Api

from apollo.conf.constant import *
from apollo.database.proxy.cve import CveProxy
from apollo.url import SPECIFIC_URLS
from vulcanus.restful.response import BaseResponse
from vulcanus.restful.resp.state import DATABASE_CONNECT_ERROR, PARAM_ERROR, SUCCEED, WRONG_FILE_FORMAT, SERVER_ERROR, \
    DATABASE_QUERY_ERROR, DATABASE_UPDATE_ERROR

API = Api()
for view, url in SPECIFIC_URLS['CVE_URLS']:
    API.add_resource(view, url)

APOLLO = Blueprint('apollo', __name__)
app = Flask("apollo")
API.init_app(APOLLO)
app.register_blueprint(APOLLO)

app.testing = True
client = app.test_client()
header = {
    "Content-Type": "application/json; charset=UTF-8"
}
header_with_token = {
    "Content-Type": "application/json; charset=UTF-8",
    "access_token": "81fe"
}
header_with_upload_file_token = {
    "Content-Type": "multipart/form-data;",
    "access_token": "81fe"
}


class VulGetCveOverviewTestCase(unittest.TestCase):
    def test_vulgetcveoverview_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.post(VUL_CVE_OVERVIEW, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')


class VulGetCveListTestCase(unittest.TestCase):
    def test_vulgetcvelist_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_CVE_LIST_GET, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    def test_vulgetcvelist_should_return_param_error_when_input_wrong_param(self):
        args = {
            "task_id": 2
        }
        response = client.post(
            VUL_CVE_LIST_GET,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(CveProxy, 'connect')
    @mock.patch.object(BaseResponse, 'verify_request')
    def test_vulgetcvelist_should_return_connect_error_when_database_error(self,
                                                                           mock_verify_request,
                                                                           mock_connect):
        mock_verify_request.return_value = {}, SUCCEED
        mock_connect.return_value = False
        response = client.post(
            VUL_CVE_LIST_GET,
            json={},
            headers=header_with_token).json
        self.assertEqual(response['label'], DATABASE_CONNECT_ERROR)


class VulGetCveInfoTestCase(unittest.TestCase):
    def test_vulgetcveinfo_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.post(VUL_CVE_INFO_GET, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    def test_vulgetcveinfo_should_return_param_error_when_input_wrong_param(self):
        response = client.get(
            VUL_CVE_INFO_GET,
            json={},
            headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(CveProxy, 'connect')
    @mock.patch.object(BaseResponse, 'verify_request')
    def test_vulgetcveinfo_should_return_connect_error_when_database_error(self,
                                                                           mock_verify_request,
                                                                           mock_connect):
        mock_verify_request.return_value = {}, SUCCEED
        mock_connect.return_value = False
        response = client.get(f'{VUL_CVE_INFO_GET}?cve_id={"1233"}',
                              headers=header_with_token).json
        self.assertEqual(response['label'], DATABASE_CONNECT_ERROR)


class VulGetCveHostsTestCase(unittest.TestCase):
    def test_vulgetcvehosts_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_CVE_HOST_GET, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    def test_vulgetcvehosts_should_return_param_error_when_input_wrong_param(self):
        args = {
            "task_id": 2
        }
        response = client.post(
            VUL_CVE_HOST_GET,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(BaseResponse, 'verify_request')
    def test_vulgetcvehosts_should_return_connect_error_when_database_query_error(self,
                                                                                  mock_verify_request):
        args = {"cve_id": "1234", "username": "admin"}
        mock_verify_request.return_value = args, SUCCEED
        response = client.post(
            VUL_CVE_HOST_GET,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], DATABASE_QUERY_ERROR)


class VulGetCveTaskHostTestCase(unittest.TestCase):
    def test_vulgetcvetaskhost_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_CVE_TASK_HOST_GET, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    def test_vulgetcvetaskhost_should_return_param_error_when_input_wrong_param(self):
        args = {
            "task_id": 2
        }
        response = client.post(
            VUL_CVE_TASK_HOST_GET,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(BaseResponse, 'verify_request')
    def test_vulgetcvetaskhost_should_return_connect_error_when_database_query_error(self,
                                                                                     mock_verify_request):
        args = {
            "cve_list": ["cve1"],
            "username": "admin"
        }
        mock_verify_request.return_value = args, SUCCEED
        response = client.post(
            VUL_CVE_TASK_HOST_GET,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], DATABASE_QUERY_ERROR)


class VulSetCveStatusTestCase(unittest.TestCase):
    def test_vulsetcvestatus_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_CVE_STATUS_SET, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    def test_vulsetcvestatus_should_return_param_error_when_input_wrong_param(self):
        args = {
            "task_id": 2
        }
        response = client.post(
            VUL_CVE_STATUS_SET,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(BaseResponse, 'verify_request')
    def test_vulsetcvestatus_should_return_connect_error_when_database_update_error(self,
                                                                                    mock_verify_request):
        args = {
            "cve_list": ["cve1"],
            "status": "on-hold",
            "username": "admin"
        }
        mock_verify_request.return_value = args, SUCCEED
        response = client.post(
            VUL_CVE_STATUS_SET,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], DATABASE_UPDATE_ERROR)


class VulGetCveActionTestCase(unittest.TestCase):
    def test_vulgetcveaction_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_CVE_ACTION_QUERY, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    def test_vulgetcveaction_should_return_param_error_when_input_wrong_param(
            self):
        args = {
            "task_id": 2
        }
        response = client.post(
            VUL_CVE_ACTION_QUERY,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)


class VulUploadAdvisoryTestCase(unittest.TestCase):
    def test_vuluploadadvisory_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_CVE_UPLOAD_ADVISORY, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    def test_vuluploadadvisory_should_return_param_error_when_input_wrong_param(self):
        args = {
            "task_id": 2
        }
        response = client.post(
            VUL_CVE_UPLOAD_ADVISORY,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)

    @mock.patch.object(CveProxy, 'connect')
    @mock.patch.object(BaseResponse, 'verify_request')
    @mock.patch.object(BaseResponse, 'verify_upload_request')
    def test_vuluploadadvisory_should_return_wrong_file_format_when_wrong_file(self,
                                                                               mock_verify_upload_request,
                                                                               mock_verify_request,
                                                                               mock_connect):
        mock_connect.return_value = True
        mock_verify_request.return_value = {}, SUCCEED
        mock_verify_upload_request.return_value = SUCCEED, "admin", "test.txt"
        response = client.post(
            VUL_CVE_UPLOAD_ADVISORY,
            headers=header_with_token).json
        self.assertEqual(response['label'], WRONG_FILE_FORMAT)


class VulUploadUnaffectedTestCase(unittest.TestCase):
    def test_vuluploadunaffected_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_CVE_UPLOAD_UNAFFECTED, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    @mock.patch.object(CveProxy, 'connect')
    @mock.patch.object(BaseResponse, 'verify_request')
    @mock.patch.object(BaseResponse, 'verify_upload_request')
    def test_vuluploadunaffected_should_return_wrong_file_format_when_wrong_file(self,
                                                                                 mock_verify_upload_request,
                                                                                 mock_verify_request,
                                                                                 mock_connect):
        mock_connect.return_value = True
        mock_verify_request.return_value = {}, SUCCEED
        mock_verify_upload_request.return_value = SUCCEED, "admin", "test.txt"
        response = client.post(
            VUL_CVE_UPLOAD_UNAFFECTED,
            headers=header_with_upload_file_token).json
        self.assertEqual(response['label'], WRONG_FILE_FORMAT)

    @mock.patch.object(BaseResponse, 'verify_request')
    def test_vuluploadunaffected_should_return_param_error_when_input_wrong_param(self,
                                                                                  mock_verify_request):
        mock_verify_request.return_value = {}, SUCCEED
        args = {
            "task_id": 2
        }
        response = client.post(
            VUL_CVE_UPLOAD_UNAFFECTED,
            json=args,
            headers=header_with_token).json
        self.assertEqual(response['label'], PARAM_ERROR)


class VulExportExcelTestCase(unittest.TestCase):
    def test_vulexportexcel_should_return_error_when_request_method_is_wrong(self):
        args = {}
        response = client.get(VUL_EXPORT_EXCEL, json=args).json
        self.assertEqual(
            response.get("data",dict())['message'], 'The method is not allowed for the requested URL.')

    @mock.patch.object(CveProxy, 'connect')
    @mock.patch.object(os.path, 'join')
    @mock.patch.object(os, 'mkdir')
    @mock.patch.object(shutil, 'rmtree')
    @mock.patch.object(BaseResponse, 'verify_request')
    def test_vulexportexcel_should_return_connect_error_when_database_error(self,
                                                                            mock_verify_request,
                                                                            mock_join,
                                                                            mock_mkdir,
                                                                            mock_rmtree,
                                                                            mock_connect):
        mock_verify_request.return_value = {}, SUCCEED
        mock_connect.return_value = False
        response = client.post(
            VUL_EXPORT_EXCEL,
            json={"host_list": [1]},
            headers=header_with_token).json
        self.assertEqual(response['label'], DATABASE_CONNECT_ERROR)

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os.path, 'join')
    @mock.patch.object(shutil, 'rmtree')
    @mock.patch.object(os, 'mkdir')
    @mock.patch.object(CveProxy, 'connect')
    @mock.patch('apollo.handler.cve_handler.view.compress_cve')
    @mock.patch.object(CveProxy, 'query_host_name_and_related_cves')
    def test_vulexportexcel_should_return_server_error_when_compress_cve_fail(self,
                                                                              mock_query_host_name_and_related_cves,
                                                                              mock_compress_cve,
                                                                              mock_connect,
                                                                              mock_mkdir,
                                                                              mock_rmtree,
                                                                              mock_join,
                                                                              mock_exists):
        mock_exists.return_value = True
        mock_connect.return_value = True
        mock_query_host_name_and_related_cves.return_value = "123.8.8.9", ["111", "222"]
        mock_compress_cve.return_value = "", ""

        response = client.post(
            VUL_EXPORT_EXCEL,
            json={"host_list": [1, 2], "username": "admin"},
            headers=header_with_token).json
        self.assertEqual(response['label'], SERVER_ERROR)
