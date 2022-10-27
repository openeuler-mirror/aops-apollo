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
Description: ansible runner
"""

class CveAnsible:
    """
    Ansible task manager.
    """

    def __init__(self, inventory=None, callback=None):
        """
        initialization
        """
        self.results_callback = callback

    @property
    def result(self):
        """
        Return the result.

        Returns:
            dict
        """
        return self.results_callback.result

    @property
    def check(self):
        """
        Return the check result.

        Returns:
            dict
        """
        return self.results_callback.check_result

    @property
    def info(self):
        """
        Return the task info.

        Returns:
            dict
        """
        return self.results_callback.task_info

    def playbook(self, playbook):
        """
        Execute playbooks

        Args:
            playbook (list): path of playbook

        Returns:
            bool
        """
        return True
