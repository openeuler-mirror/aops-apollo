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
from vulcanus.restful.resp.state import SUCCEED, DATABASE_INSERT_ERROR

from apollo.conf import configuration
from apollo.cron.download_sa_manager import TimedDownloadSATask
from apollo.database.proxy.cve import CveProxy


class TestDownloadSecurityManage(unittest.TestCase):
    @mock.patch.object(CveProxy, "connect")
    def test_task_enter_should_return_None_when_database_connect_fail(self, mock_connect):
        mock_connect.return_value = False
        self.assertEqual(TimedDownloadSATask.task_enter(), None)

    @mock.patch.object(os, "listdir")
    def test_save_security_advisory_to_database_should_return_None_when_dir_is_None(self, mock_listdir):
        proxy = CveProxy(configuration)
        mock_listdir.return_value = []
        self.assertEqual(TimedDownloadSATask.save_security_advisory_to_database(proxy), None)

    @mock.patch.object(os, "listdir")
    @mock.patch.object(os.path, "join")
    @mock.patch.object(re, "findall")
    @mock.patch("apollo.cron.download_sa_manager.parse_security_advisory")
    @mock.patch.object(CveProxy, "save_security_advisory")
    @mock.patch.object(shutil, "rmtree")
    def test_save_security_advisory_to_database_should_return_None_when_parse_security_advisory_fail(
        self,
        mock_rmtree,
        mock_save_security_advisory,
        mock_parse_security_advisory,
        mock_findall,
        mock_join,
        mock_listdir,
    ):
        proxy = CveProxy(configuration)
        TimedDownloadSATask.save_sa_record = []
        mock_listdir.return_value = list(range(2))
        mock_join.return_value = "mock"
        mock_findall.return_value = ["2022", "1112"]
        mock_parse_security_advisory.side_effect = KeyError
        mock_save_security_advisory.return_value = None
        TimedDownloadSATask.save_security_advisory_to_database(proxy)
        self.assertEqual(
            TimedDownloadSATask.save_sa_record,
            [
                {"advisory_year": "2022", "advisory_serial_number": "1112", "download_status": False},
                {"advisory_year": "2022", "advisory_serial_number": "1112", "download_status": False},
            ],
        )

    @mock.patch.object(os, "listdir")
    @mock.patch.object(os.path, "join")
    @mock.patch.object(re, "findall")
    @mock.patch("apollo.cron.download_sa_manager.parse_security_advisory")
    @mock.patch.object(CveProxy, "save_security_advisory")
    @mock.patch.object(shutil, "rmtree")
    def test_save_security_advisory_to_database_should_return_None_when_parse_security_advisory_ok(
        self,
        mock_rmtree,
        mock_save_security_advisory,
        mock_parse_security_advisory,
        mock_findall,
        mock_join,
        mock_listdir,
    ):
        proxy = CveProxy(configuration)
        TimedDownloadSATask.save_sa_record = []
        mock_listdir.return_value = list(range(2))
        mock_join.return_value = "mock"
        mock_findall.return_value = ["2022", "1112"]
        mock_parse_security_advisory.return_value = ["mock"], ["mock"], ["mock"], "mock", "mock"
        mock_save_security_advisory.return_value = SUCCEED
        TimedDownloadSATask.save_security_advisory_to_database(proxy)
        self.assertEqual(
            TimedDownloadSATask.save_sa_record,
            [
                {"advisory_year": "2022", "advisory_serial_number": "1112", "download_status": True},
                {"advisory_year": "2022", "advisory_serial_number": "1112", "download_status": True},
            ],
        )
        TimedDownloadSATask.save_sa_record = []
        mock_save_security_advisory.return_value = DATABASE_INSERT_ERROR
        TimedDownloadSATask.save_security_advisory_to_database(proxy)
        self.assertEqual(
            TimedDownloadSATask.save_sa_record,
            [
                {"advisory_year": "2022", "advisory_serial_number": "1112", "download_status": False},
                {"advisory_year": "2022", "advisory_serial_number": "1112", "download_status": False},
            ],
        )

    @mock.patch.object(requests, "get")
    def test_get_response_should_return_None_when_request_fail(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException
        url = "http://www.baidu.com/3434"
        self.assertEqual(TimedDownloadSATask.get_response(url), "")

    @mock.patch.object(os.path, "exists")
    @mock.patch.object(shutil, "rmtree")
    @mock.patch.object(os, "makedirs")
    @mock.patch.object(re, "findall")
    @mock.patch.object(TimedDownloadSATask, "get_response")
    def test_download_security_advisory_should_return_succeed_when_keyerror(
        self, mock_get_response, mock_findall, mock_makedirs, mock_rmtree, mock_exists
    ):
        TimedDownloadSATask.save_sa_record = []
        mock_get_response.return_value = ""
        mock_findall.return_value = ["2022", "1111"]
        TimedDownloadSATask.download_security_advisory(["mock"])
        self.assertEqual(
            TimedDownloadSATask.save_sa_record,
            [{"advisory_year": "2022", "advisory_serial_number": "1111", "download_status": False}],
        )

        TimedDownloadSATask.save_sa_record = []
        mock_get_response.return_value = None
        mock_findall.return_value = ["2022", "1111"]
        TimedDownloadSATask.download_security_advisory(["mock"])
        self.assertEqual(
            TimedDownloadSATask.save_sa_record,
            [{"advisory_year": "2022", "advisory_serial_number": "1111", "download_status": False}],
        )

    @mock.patch.object(TimedDownloadSATask, "get_response")
    def test_get_advisory_url_list_should_return_none_list_when_request_failed(self, mock_get_response):
        mock_get_response.return_value = ""
        self.assertEqual(TimedDownloadSATask.get_advisory_url_list("mock"), [])

    @mock.patch.object(TimedDownloadSATask, "get_advisory_url_list")
    def test_get_incremental_advisory_url_list_should_return_list_when_requests_failed(
        self, mock_get_advisory_url_list
    ):
        TimedDownloadSATask.advisory_years = ["2021"]
        TimedDownloadSATask.security_base_url = "https://repo.openeuler.org/security/data/cvrf"
        mock_get_advisory_url_list.return_value = []
        download_succeed_record = []
        for i in range(2):
            record = mock.Mock()
            record.advisory_year = "2022"
            record.advisory_serial_number = str(1121 + i)
            download_succeed_record.append(record)
        self.assertEqual(TimedDownloadSATask.get_incremental_sa_name_list(download_succeed_record), [])

        mock_get_advisory_url_list.return_value = [
            "cvrf-openEuler-SA-2022-1123.xml",
            "cvrf-openEuler-SA-2022-1121.xml",
            "cvrf-openEuler-SA-2022-1122.xml",
        ]
        download_succeed_record = []
        for i in range(2):
            record = mock.Mock()
            record.advisory_year = "2022"
            record.advisory_serial_number = str(1121 + i)
            download_succeed_record.append(record)
        self.assertEqual(
            TimedDownloadSATask.get_incremental_sa_name_list(download_succeed_record),
            ["cvrf-openEuler-SA-2022-1123.xml"],
        )
