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

import unittest
from unittest import mock
from unittest.mock import Mock

from apollo.conf import configuration
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.callback.cve_fix import CveFixCallback


class CveFixCallbackTestCase(unittest.TestCase):
    @mock.patch.object(TaskProxy, 'set_cve_progress')
    @mock.patch.object(TaskProxy, 'update_cve_status')
    def test_callback_should_correct(self, mock_update_cve_status, mock_set_cve_progress):
        proxy = TaskProxy(configuration)
        fake_task_id = Mock()
        fake_host_id = Mock()
        fake_cves = {"cve1": "fixed", "cve2": "unfixed"}
        callback = CveFixCallback(proxy)
        callback.callback(fake_task_id, fake_host_id, fake_cves)
        self.assertEqual(mock_update_cve_status.call_count, 2)
        mock_set_cve_progress.assert_called_with(fake_task_id, list(fake_cves.keys()))


if __name__ == '__main__':
    unittest.main()
