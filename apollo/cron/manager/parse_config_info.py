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

import configparser

from apollo.conf.constant import TIMED_TASK_CONFIG_PATH


def get_timed_task_config_info():
    """
    Parsing the configuration file information of a timed task

    Returns:
        list: list of dict, each dict is a timed task info, e.g.:
            [
                {'id': 'task id1', 'trigger': 'cron', 'day_of_week': '0-6', 'hour': '2', 'auto_start': 'True'},
                {'id': 'task id1', 'trigger': 'cron', 'day_of_week': '0-6', 'hour': '3', 'auto_start': 'True'},
                {'id': 'task id1', 'trigger': 'cron', 'day_of_week': '0-6', 'hour': '4', 'auto_start': 'True'}
            ]
    """
    config = configparser.ConfigParser()
    config.read(TIMED_TASK_CONFIG_PATH)

    config_info = []
    section_list = config.sections()
    for section in section_list:
        config_info.append(dict(config.items(section)))

    return config_info
