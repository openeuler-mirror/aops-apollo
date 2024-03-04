#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
from dataclasses import dataclass


@dataclass
class SecurityCvrfInfo:
    """SecurityCvrfInfo - model defined
    Args:
        cve_rows: list of dict to insert to mysql Cve table
        cve_pkg_rows: list of dict to insert to mysql CveAffectedPkgs table
        cve_pkg_docs: list of dict to insert to es CVE_INDEX
        sa_year: security advisory year
        sa_number: security advisory order number

    """
    cve_rows: list
    cve_pkg_rows: list
    cve_pkg_docs: list
    sa_year: str
    sa_number: str


@dataclass
class SplitTask:
    """SplitTask - model defined
    Args:
        repo_task: repo task list
        cve_task: cve task list
        cve_rollback_task: cve rollback task list
        hp_remove_task: hotpatch remove task list

    """
    repo_task: list
    cve_task: list
    cve_rollback_task: list
    hp_remove_task: list
