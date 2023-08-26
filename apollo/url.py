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
Description: url set
"""
from apollo.conf.constant import *
from apollo.handler.cve_handler import view as cve_view
from apollo.handler.host_handler import view as cve_host_view
from apollo.handler.repo_handler import view as cve_repo_view
from apollo.handler.task_handler import view as cve_task_view

URLS = []

SPECIFIC_URLS = {
    "CVE_REPO_URLS": [
        (cve_repo_view.VulImportYumRepo, VUL_REPO_IMPORT),
        (cve_repo_view.VulGetYumRepo, VUL_REPO_GET),
        (cve_repo_view.VulDeleteYumRepo, VUL_REPO_DELETE),
        (cve_repo_view.VulGetRepoTemplate, VUL_REPO_TEMPLATE_GET),
    ],
    "CVE_URLS": [
        (cve_view.VulGetCveOverview, VUL_CVE_OVERVIEW),
        (cve_view.VulGetCveList, VUL_CVE_LIST_GET),
        (cve_view.VulGetCveInfo, VUL_CVE_INFO_GET),
        (cve_view.VulGetCveHosts, VUL_CVE_HOST_GET),
        (cve_view.VulGetCveTaskHost, VUL_CVE_TASK_HOST_GET),
        (cve_view.VulUploadAdvisory, VUL_CVE_UPLOAD_ADVISORY),
        (cve_view.VulUploadUnaffected, VUL_CVE_UPLOAD_UNAFFECTED),
        (cve_view.VulExportExcel, VUL_EXPORT_EXCEL),
    ],
    "CVE_HOST_URLS": [
        (cve_host_view.VulGetHostStatus, VUL_HOST_STATUS_GET),
        (cve_host_view.VulGetHostList, VUL_HOST_LIST_GET),
        (cve_host_view.VulGetHostInfo, VUL_HOST_INFO_GET),
        (cve_host_view.VulGetHostCves, VUL_HOST_CVE_GET),
    ],
    "CVE_TASK_URLS": [
        (cve_task_view.VulScanHost, VUL_HOST_SCAN),
        (cve_task_view.VulGetTaskList, VUL_TASK_LIST_GET),
        (cve_task_view.VulGetTaskProgress, VUL_TASK_PROGRESS_GET),
        (cve_task_view.VulGetTaskInfo, VUL_TASK_INFO_GET),
        (cve_task_view.VulGenerateCveTask, VUL_TASK_CVE_GENERATE),
        (cve_task_view.VulGetCveTaskInfo, VUL_TASK_CVE_INFO_GET),
        (cve_task_view.VulGetCveTaskStatus, VUL_TASK_CVE_STATUS_GET),
        (cve_task_view.VulGetCveTaskProgress, VUL_TASK_CVE_PROGRESS_GET),
        (cve_task_view.VulGetCveTaskResult, VUL_TASK_CVE_RESULT_GET),
        (cve_task_view.VulExecuteTask, VUL_TASk_EXECUTE),
        (cve_task_view.VulGenerateRepoTask, VUL_TASK_REPO_GENERATE),
        (cve_task_view.VulGetRepoTaskInfo, VUL_TASK_REPO_INFO_GET),
        (cve_task_view.VulGetRepoTaskResult, VUL_TASK_REPO_RESULT_GET),
        (cve_task_view.VulDeleteTask, VUL_TASK_DELETE),
        (cve_task_view.VulGenerateCveRollback, VUL_TASK_CVE_ROLLBACK_GENERATE),
        (cve_task_view.VulGetTaskCveRpmInfo, VUL_TASK_CVE_RPM_INFO_GET),
    ],
    "CVE_TASK_CALLBACK_URLS": [
        (cve_task_view.VulCveFixTaskCallback, VUL_TASK_CVE_FIX_CALLBACK),
        (cve_task_view.VulRepoSetTaskCallback, VUL_TASK_REPO_SET_CALLBACK),
        (cve_task_view.VulCveScanTaskCallback, VUL_TASK_CVE_SCAN_CALLBACK),
        (cve_task_view.VulCveRollbackTaskCallback, VUL_TASK_CVE_ROLLBACK_CALLBACK),
    ],
}

for _, value in SPECIFIC_URLS.items():
    URLS.extend(value)
