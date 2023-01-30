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

from vulcanus.log.log import LOGGER


def get_timed_task_config_info(file_path: str):
    """
    Parsing the configuration file information of a timed task

    Args:
        file_path(str): Path to the configuration file

    Returns:
        list: list of dict, each dict is a parsing results, e.g.:
            [
                {'id': 'task id1', 'trigger': 'cron', 'day_of_week': '0-6', 'hour': '2'},
                {'id': 'task id1', 'trigger': 'cron', 'day_of_week': '0-6', 'hour': '3'},
                {'id': 'task id1', 'trigger': 'cron', 'day_of_week': '0-6', 'hour': '4'}
            ]
    """
    config = configparser.ConfigParser()
    try:
        config.read(file_path)
    except FileNotFoundError as error:
        LOGGER.error(error)
        LOGGER.error("configuration file path error")
        return []
    config_info = []
    section_list = config.sections()
    for section in section_list:
        config_info.append(dict(config.items(section)))

    return config_info
