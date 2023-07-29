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
"""
Time:
Author:
Description:
"""

from apollo.handler.task_handler.callback.cve_rollback import CveRollbackCallback
from apollo.database.proxy.task import TaskMysqlProxy
from apollo.tests import BaseTestCase


class TestCveRollbackCallback(BaseTestCase):
    def setUp(self):
        super().setUp()
        task_info = {"cve": {"cve1": 1, "cve2": 2}, "host": {"name1": {"host_id": 1}, "name2": {"host_id": 2}}}
        proxy = TaskMysqlProxy()
        self.call = CveRollbackCallback('1', proxy, task_info)

    def tearDown(self):
        pass

    # @mock.patch.object(TaskMysqlProxy, 'set_cve_progress')
    # @mock.patch.object(TaskMysqlProxy, 'update_cve_status')
    # def test_result(self, mock_update_cve_status, mock_set_cve_progress):
    #     result1 = Test(Host('name1'), {'stdout': "11"}, "cve1")
    #     self.call.v2_runner_on_unreachable(result1)

    #     result2 = Test(Host('name1'), {'stdout': "12"}, "check1")
    #     self.call.v2_runner_on_ok(result2)

    #     result3 = Test(Host('name1'), {'stderr': "13"}, "cve2")
    #     self.call.v2_runner_on_failed(result3)

    #     expected_res = {
    #         "name1": {
    #             "cve1": {"info": "11", "status": CVE_HOST_STATUS.FIXED},
    #             "cve2": {"info": "13", "status": CVE_HOST_STATUS.FIXED},
    #         }
    #     }
    #     self.assertDictEqual(expected_res, self.call.result)
