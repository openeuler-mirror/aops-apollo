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
import os
import re
import shutil
import unittest
from unittest import mock

import requests
from lxml import etree

from apollo.conf import configuration
from apollo.cron.download_sa_manager import TimedDownloadSATask
from apollo.database.proxy.cve import CveProxy
from vulcanus.restful.resp.state import DATABASE_CONNECT_ERROR, SUCCEED, DATABASE_DELETE_ERROR


class TestDownloadSecurityManage(unittest.TestCase):

    @mock.patch.object(CveProxy, "connect")
    def test_task_enter_should_return_content_error_when_database_connect_fail(self,
                                                                               mock_connect):
        mock_connect.return_value = False
        self.assertEqual(TimedDownloadSATask.task_enter(), DATABASE_CONNECT_ERROR)

    @mock.patch.object(CveProxy, "get_advisory_download_record")
    @mock.patch.object(TimedDownloadSATask, "download_security_advisory")
    @mock.patch.object(TimedDownloadSATask, "get_incremental_advisory_url_list")
    def test_task_enter_should_return_content_error_when_download_security_advisory_fail(self,
                                                                                         mock_get_incremental_advisory_url_list,
                                                                                         mock_download_security_advisory,
                                                                                         mock_get_advisory_download_record, ):
        TimedDownloadSATask.advisory_years = ["2021"]
        TimedDownloadSATask.security_base_url = mock.Mock()
        download_record = mock.Mock()
        download_record.id = 1
        download_record.advisory_year = "2022"
        download_record.advisory_serial_number = "2152"
        mock_get_advisory_download_record.return_value = [download_record], [download_record]
        mock_get_incremental_advisory_url_list.return_value = []
        mock_download_security_advisory.return_value = DATABASE_CONNECT_ERROR
        self.assertEqual(TimedDownloadSATask.task_enter(), DATABASE_CONNECT_ERROR)

    @mock.patch.object(CveProxy, "connect")
    @mock.patch.object(CveProxy, "get_advisory_download_record")
    @mock.patch.object(TimedDownloadSATask, "download_security_advisory")
    @mock.patch.object(TimedDownloadSATask, "get_incremental_advisory_url_list")
    @mock.patch.object(TimedDownloadSATask, "save_security_advisory_to_database")
    @mock.patch.object(CveProxy, "delete_advisory_download_failed_record")
    def test_task_enter_should_return_delete_error_when_delete_advisory_download_failed_record_fail(self,
                                                                                                    mock_delete_advisory_download_failed_record,
                                                                                                    mock_save_security_advisory_to_database,
                                                                                                    mock_get_incremental_advisory_url_list,
                                                                                                    mock_download_security_advisory,
                                                                                                    mock_get_advisory_download_record,
                                                                                                    mock_connect):
        TimedDownloadSATask.advisory_years = ["2021"]
        TimedDownloadSATask.security_base_url = mock.Mock()
        mock_connect.return_value = True
        download_record = mock.Mock()
        download_record.id = 1
        download_record.advisory_year = "2022"
        download_record.advisory_serial_number = "2152"
        mock_get_advisory_download_record.return_value = [download_record], [download_record]
        mock_get_incremental_advisory_url_list.return_value = []
        mock_download_security_advisory.return_value = SUCCEED
        mock_save_security_advisory_to_database.return_value = SUCCEED
        mock_delete_advisory_download_failed_record.return_value = DATABASE_DELETE_ERROR
        self.assertEqual(TimedDownloadSATask.task_enter(), DATABASE_DELETE_ERROR)

    @mock.patch.object(os, "listdir")
    def test_save_security_advisory_to_database_should_return_succeed_when_no_advisory_need_save(self,
                                                                                                 mock_listdir):
        proxy = CveProxy(configuration)
        mock_listdir.return_value = []
        self.assertEqual(TimedDownloadSATask.save_security_advisory_to_database(proxy, [mock.Mock()]), SUCCEED)

    @mock.patch.object(os, "listdir")
    @mock.patch.object(os.path, "join")
    @mock.patch("apollo.handler.cve_handler.manager.parse_advisory.parse_security_advisory")
    @mock.patch.object(CveProxy, "save_security_advisory")
    @mock.patch.object(re, "findall")
    @mock.patch.object(shutil, "rmtree")
    @mock.patch.object(CveProxy, "update_advisory_download_record")
    def test_save_security_advisory_to_database_should_return_succeed_when_update_advisory_download_record_ok(self,
                                                                                                              mock_update_advisory_download_record,
                                                                                                              mock_rmtree,
                                                                                                              mock_findall,
                                                                                                              mock_save_security_advisory,
                                                                                                              mock_parse_security_advisory,
                                                                                                              mock_join,
                                                                                                              mock_listdir):
        proxy = CveProxy(configuration)
        mock_listdir.return_value = list(range(10))
        mock_join.return_value = "mock"
        mock_parse_security_advisory.return_value = [], [], []
        mock_save_security_advisory.return_value = None
        mock_findall.return_value = "mock", "mock"
        mock_update_advisory_download_record.return_value = None

        self.assertEqual(TimedDownloadSATask.save_security_advisory_to_database(proxy, [mock.Mock()]), SUCCEED)

    @mock.patch.object(os, "listdir")
    @mock.patch.object(os.path, "join")
    @mock.patch("apollo.handler.cve_handler.manager.parse_advisory.parse_security_advisory")
    @mock.patch.object(CveProxy, "save_security_advisory")
    @mock.patch.object(re, "findall")
    @mock.patch.object(shutil, "rmtree")
    @mock.patch.object(CveProxy, "insert_advisory_download_record")
    def test_save_security_advisory_to_database_should_return_succeed_when_insert_advisory_download_record_ok(self,
                                                                                                              mock_insert_advisory_download_record,
                                                                                                              mock_rmtree,
                                                                                                              mock_findall,
                                                                                                              mock_save_security_advisory,
                                                                                                              mock_parse_security_advisory,
                                                                                                              mock_join,
                                                                                                              mock_listdir):
        proxy = CveProxy(configuration)
        mock_listdir.return_value = list(range(10))
        mock_join.return_value = "mock"
        mock_parse_security_advisory.return_value = [], [], []
        mock_save_security_advisory.return_value = None
        mock_findall.return_value = "mock", "mock"
        mock_insert_advisory_download_record.return_value = None

        self.assertEqual(TimedDownloadSATask.save_security_advisory_to_database(proxy, []), SUCCEED)

    @mock.patch.object(os, "listdir")
    @mock.patch.object(os.path, "join")
    @mock.patch("apollo.handler.cve_handler.manager.parse_advisory.parse_security_advisory")
    @mock.patch.object(CveProxy, "save_security_advisory")
    @mock.patch.object(re, "findall")
    @mock.patch.object(shutil, "rmtree")
    @mock.patch.object(CveProxy, "update_advisory_download_record")
    def test_save_security_advisory_to_database_should_return_succeed_when_save_succeed(self,
                                                                                        mock_update_advisory_download_record,
                                                                                        mock_rmtree,
                                                                                        mock_findall,
                                                                                        mock_save_security_advisory,
                                                                                        mock_parse_security_advisory,
                                                                                        mock_join,
                                                                                        mock_listdir):
        proxy = CveProxy(configuration)
        mock_listdir.return_value = list(range(10))
        mock_join.return_value = "mock"
        mock_parse_security_advisory.return_value = [], [], []
        mock_save_security_advisory.side_effect = KeyError
        mock_findall.return_value = "mock", "mock"
        mock_update_advisory_download_record.return_value = None

        self.assertEqual(TimedDownloadSATask.save_security_advisory_to_database(proxy, [mock.Mock()]), SUCCEED)

    @mock.patch.object(CveProxy, "connect")
    def test_download_security_advisory_should_return_connect_error_when_database_connect_error(self,
                                                                                                mock_connect):
        mock_connect.return_value = False
        self.assertEqual(TimedDownloadSATask.download_security_advisory([]), DATABASE_CONNECT_ERROR)

    @mock.patch.object(CveProxy, "connect")
    @mock.patch.object(os.path, "exists")
    @mock.patch.object(shutil, "rmtree")
    @mock.patch.object(os, "makedirs")
    @mock.patch.object(requests, "get")
    @mock.patch.object(re, "findall")
    @mock.patch.object(CveProxy, "insert_advisory_download_record")
    def test_download_security_advisory_should_return_succeed_when_keyerror(self,
                                                                            mock_insert_advisory_download_record,
                                                                            mock_findall,
                                                                            mock_get,
                                                                            mock_makedirs,
                                                                            mock_rmtree,
                                                                            mock_exists,
                                                                            mock_connect):
        mock_connect.return_value = True
        response = mock.Mock()
        response.status_code = "failed"
        mock_get.return_value = response
        mock_findall.return_value = "mock", "mock"
        mock_insert_advisory_download_record.return_value = None

        self.assertEqual(TimedDownloadSATask.download_security_advisory(["mock/mock"]), SUCCEED)

    @mock.patch.object(CveProxy, "connect")
    @mock.patch.object(os.path, "exists")
    @mock.patch.object(shutil, "rmtree")
    @mock.patch.object(os, "makedirs")
    @mock.patch.object(requests, "get")
    @mock.patch.object(re, "findall")
    @mock.patch.object(os.path, "join")
    @mock.patch.object(CveProxy, "insert_advisory_download_record")
    def test_download_security_advisory_should_return_succeed_when_download_succeed(self,
                                                                                    mock_insert_advisory_download_record,
                                                                                    mock_join,
                                                                                    mock_findall,
                                                                                    mock_get,
                                                                                    mock_makedirs,
                                                                                    mock_rmtree,
                                                                                    mock_exists,
                                                                                    mock_connect):
        mock_connect.return_value = True
        response = mock.Mock()
        response.status_code = "ok"
        mock_get.return_value = response
        mock_findall.return_value = "mock", "mock"
        mock_insert_advisory_download_record.return_value = None

        self.assertEqual(TimedDownloadSATask.download_security_advisory(["mock/mock"]), SUCCEED)

    @mock.patch.object(requests, "get")
    def test_get_advisory_url_list_should_return_none_list_when_request_failed(self,
                                                                               mock_get):
        response = mock.Mock()
        response.status_code = "failed"
        mock_get.return_value = response
        self.assertEqual(TimedDownloadSATask.get_advisory_url_list("mock"), [])

    @mock.patch.object(requests, "get")
    @mock.patch.object(etree, "HTML")
    def test_get_advisory_url_list_should_return_none_list_when_parse_html_failed(self,
                                                                                  mock_HTML,
                                                                                  mock_get):
        response = mock.Mock()
        response.status_code = "ok"
        mock_get.return_value = response
        mock_HTML.side_effect = AttributeError
        self.assertEqual(TimedDownloadSATask.get_advisory_url_list("mock"), [])

    @mock.patch.object(requests, "get")
    def test_get_incremental_advisory_url_list_should_return_list_when_requests_failed(self,
                                                                                       mock_get):
        TimedDownloadSATask.advisory_years = ["2021"]
        TimedDownloadSATask.security_base_url = "https://repo.openeuler.org/security/data/cvrf"
        response = mock.Mock()
        response.status_code = "failed"
        mock_get.return_value = response

        record_query = []
        record = mock.Mock()
        for i in range(5):
            record.advisory_serial_number = 1000 + i
            record.advisory_year = 2022
            record_query.append(record)

        self.assertEqual(TimedDownloadSATask.get_incremental_advisory_url_list(record_query), [])

    @mock.patch.object(requests, "get")
    @mock.patch.object(TimedDownloadSATask, "get_advisory_url_list")
    def test_get_incremental_advisory_url_list_should_return_list_when_not_current_year(self,
                                                                                        mock_get_advisory_url_list,
                                                                                        mock_get):
        TimedDownloadSATask.advisory_years = ["2021"]
        TimedDownloadSATask.security_base_url = "https://repo.openeuler.org/security/data/cvrf"
        response = mock.Mock()
        response.status_code = "failed"
        mock_get.return_value = response

        mock_get_advisory_url_list.return_value = []

        record_query = []
        record = mock.Mock()
        for i in range(5):
            record.advisory_serial_number = 1000 + i
            record.advisory_year = 2021
            record_query.append(record)

        self.assertEqual(TimedDownloadSATask.get_incremental_advisory_url_list(record_query), [])

    @mock.patch.object(requests, "get")
    @mock.patch.object(TimedDownloadSATask, "get_advisory_url_list")
    def test_get_incremental_advisory_url_list_should_return_list_when_succeed(self,
                                                                               mock_get_advisory_url_list,
                                                                               mock_get):
        TimedDownloadSATask.advisory_years = []
        TimedDownloadSATask.security_base_url = "https://repo.openeuler.org/security/data/cvrf"
        response = mock.Mock()
        response.status_code = "succeed"
        mock_get.return_value = response

        mock_get_advisory_url_list.return_value = ["mock"]

        record_query = []
        record = mock.Mock()
        for i in range(5):
            record.advisory_serial_number = 1000 + i
            record.advisory_year = 2022
            record_query.append(record)

        self.assertEqual(TimedDownloadSATask.get_incremental_advisory_url_list(record_query), ["mock"])
