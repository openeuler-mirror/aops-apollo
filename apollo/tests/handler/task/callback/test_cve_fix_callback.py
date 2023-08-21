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

from unittest import mock
from sqlalchemy.exc import SQLAlchemyError

from vulcanus.restful.resp.state import SUCCEED, DATABASE_UPDATE_ERROR
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.callback.cve_fix import CveFixCallback
from apollo.tests import BaseTestCase


class CveFixCallbackTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        task_proxy = TaskProxy()
        task_proxy.connect()
        self.cve_fix_callback = CveFixCallback(proxy=task_proxy)
        self.callback_result = {
            "task_id": "string",
            "host_id": "string",
            "check_items": [{"item": "network", "result": True, "log": "xxxx"}],
            "cves": [
                {
                    "cve_id": "string",
                    "result": "succeed",
                    "rpms": [
                        {
                            "rpm": "string",
                            "result": "string",
                            "log": "string",
                        }
                    ],
                }
            ],
            "host_ip": "172.168.63.86",
            "host_name": "host1_12001",
            "status": "fail",
        }

    @mock.patch.object(TaskProxy, "_set_package_status")
    @mock.patch.object(TaskProxy, '_update_cve_host_status')
    def test_callback_should_succeed_when_update_success(self, mock_update_cve_host_status, mock_set_package_status):
        mock_update_cve_host_status.return_value = SUCCEED
        mock_set_package_status.return_value = SUCCEED
        self.assertEqual(self.cve_fix_callback.callback(cve_fix_result=self.callback_result), SUCCEED)

    @mock.patch.object(TaskProxy, '_update_cve_host_status')
    def test_callback_should_error_when_update_status_fail(self, mock_update_cve_host_status):
        mock_update_cve_host_status.side_effect = SQLAlchemyError()
        self.assertEqual(self.cve_fix_callback.callback(cve_fix_result=self.callback_result), DATABASE_UPDATE_ERROR)

    @mock.patch.object(TaskProxy, "_set_package_status")
    @mock.patch.object(TaskProxy, '_update_cve_host_status')
    def test_callback_should_error_when_update_package_status_fail(
        self, mock_update_cve_host_status, mock_set_package_status
    ):
        mock_update_cve_host_status.return_value = SUCCEED
        mock_set_package_status.side_effect = SQLAlchemyError()
        self.assertEqual(self.cve_fix_callback.callback(cve_fix_result=self.callback_result), DATABASE_UPDATE_ERROR)
