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
Description: Export data to Excel
"""
import csv

from vulcanus.log.log import LOGGER

__all__ = ["export_csv"]


def export_csv(export_list: list, cve_name: str, cve_head: list):
    """
    The original data export to excel
    Args:
        export_list: The original data;e.g:
            [[
                "CVE-2018-16301",
                "affected" or "unaffected",
                "fixed" or "unfixed"
            ]]
    Returns:
        :param table_name: excel name
        :param columns_map: excel headers; e.g:
            ["cve_id", "status", "fix_status"]
    """
    try:
        with open(cve_name, 'a', encoding='utf8', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(cve_head)

            for item in export_list:
                writer.writerow(item)
    except IOError as error:
        LOGGER.error(f"Export cve info failed: %s", error)
