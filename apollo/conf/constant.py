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
Description: manager constant
"""
import os

from vulcanus.conf.constant import BASE_CONFIG_PATH


# path of apollo configuration
CVE_MANAGER_CONFIG_PATH = os.path.join(BASE_CONFIG_PATH, 'apollo.ini')

# template repo for downloading
TEMPLATE_REPO_STR = (
    "[aops-update]\n"
    "name=update\n"
    "baseurl=https://repo.openeuler.org/openEuler-22.03-LTS/update/$basearch/\n"
    "enabled=1\n"
    "gpgcheck=1\n"
    "gpgkey=https://repo.openeuler.org/openEuler-22.03-LTS/OS/$basearch/RPM-"
    "GPG-KEY-openEuler"
)


class CveHostStatus:
    SUCCEED = "succeed"
    FAIL = "fail"
    RUNNING = "running"
    UNKNOWN = "unknown"

    @staticmethod
    def attribute():
        return [CveHostStatus.SUCCEED, CveHostStatus.FAIL, CveHostStatus.RUNNING, CveHostStatus.UNKNOWN]


class RepoStatus:
    SUCCEED = "set"
    FAIL = "unset"
    RUNNING = "running"
    UNKNOWN = "unknown"


class HostStatus:
    ONLINE = 0
    OFFLINE = 1
    UNESTABLISHED = 2
    SCANNING = 3
    DONE = 4
    UNKNOWN = 5


class CvssScore:
    HIGH = 9
    MEDIUM = 7
    LOW = 4
    NONE = 0


class CveSeverity:
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"

    @staticmethod
    def attribute():
        return [CveSeverity.CRITICAL, CveSeverity.HIGH, CveSeverity.MEDIUM, CveSeverity.LOW, CveSeverity.UNKNOWN]


class TaskType:
    CVE_FIX = "cve fix"
    CVE_ROLLBACK = "cve rollback"
    REPO_SET = "repo set"

    @staticmethod
    def attribute():
        return [TaskType.CVE_FIX, TaskType.CVE_ROLLBACK, TaskType.REPO_SET]


class TaskStatus(CveHostStatus):
    pass


# route of repo related interface
VUL_REPO_IMPORT = "/vulnerability/repo/import"
VUL_REPO_GET = "/vulnerability/repo/get"
VUL_REPO_UPDATE = "/vulnerability/repo/update"
VUL_REPO_DELETE = "/vulnerability/repo/delete"
VUL_REPO_TEMPLATE_GET = "/vulnerability/repo/template/get"

# route of cve related interface
VUL_CVE_OVERVIEW = "/vulnerability/cve/overview"
VUL_CVE_LIST_GET = "/vulnerability/cve/list/get"
VUL_CVE_INFO_GET = "/vulnerability/cve/info/get"
VUL_CVE_HOST_GET = "/vulnerability/cve/host/get"
VUL_CVE_TASK_HOST_GET = "/vulnerability/cve/task/host/get"
VUL_CVE_STATUS_SET = "/vulnerability/cve/status/set"
VUL_CVE_UPLOAD_ADVISORY = "/vulnerability/cve/advisory/upload"
VUL_CVE_UPLOAD_UNAFFECTED = "/vulnerability/cve/unaffected/upload"
VUL_EXPORT_EXCEL = "/vulnerability/cve/info/export"

# route of host related interface
VUL_HOST_SCAN = "/vulnerability/host/scan"
VUL_HOST_STATUS_GET = "/vulnerability/host/status/get"
VUL_HOST_LIST_GET = "/vulnerability/host/list/get"
VUL_HOST_INFO_GET = "/vulnerability/host/info/get"
VUL_HOST_CVE_GET = "/vulnerability/host/cve/get"

# route of task related interface
VUL_TASK_LIST_GET = "/vulnerability/task/list/get"
VUL_TASK_PROGRESS_GET = "/vulnerability/task/progress/get"
VUL_TASK_INFO_GET = "/vulnerability/task/info/get"
VUL_TASK_CVE_GENERATE = "/vulnerability/task/cve-fix/generate"
VUL_TASK_CVE_INFO_GET = "/vulnerability/task/cve/info/get"
VUL_TASK_CVE_STATUS_GET = "/vulnerability/task/cve/status/get"
VUL_TASK_CVE_PROGRESS_GET = "/vulnerability/task/cve/progress/get"
VUL_TASK_CVE_RESULT_GET = "/vulnerability/task/cve/result/get"
VUL_TASk_EXECUTE = "/vulnerability/task/execute"
VUL_TASK_REPO_GENERATE = "/vulnerability/task/repo/generate"
VUL_TASK_REPO_INFO_GET = "/vulnerability/task/repo/info/get"
VUL_TASK_REPO_RESULT_GET = "/vulnerability/task/repo/result/get"
VUL_TASK_DELETE = "/vulnerability/task/delete"
VUL_TASK_CVE_ROLLBACK_GENERATE = "/vulnerability/task/cve-rollback/generate"
VUL_TASK_CVE_RPM_INFO_GET = "/vulnerability/task/cve/rpm/get"

# route of callback
VUL_TASK_CVE_FIX_CALLBACK = "/vulnerability/task/callback/cve/fix"
VUL_TASK_REPO_SET_CALLBACK = "/vulnerability/task/callback/repo/set"
VUL_TASK_CVE_SCAN_CALLBACK = "/vulnerability/task/callback/cve/scan"
VUL_TASK_CVE_ROLLBACK_CALLBACK = "/vulnerability/task/callback/cve/rollback"
VUL_TASK_CVE_SCAN_NOTICE = "/vulnerability/task/callback/cve/scan/notice"
# elasticsearch index
CVE_INDEX = 'cve'
TASK_INDEX = "task"

# elasticsearch testcase run flag. NEVER TURN IT TO TRUE IN PRODUCTION ENVIRONMENT.
# The test cases will remove the all the data of the es.
ES_TEST_FLAG = False

REPO_FILE = "/etc/yum.repos.d/aops-update.repo"
FILE_NUMBER = 1
FILE_UPLOAD_PATH = "/opt/aops/cve/upload"
CSV_SAVED_PATH = "/opt/aops/cve/saved"
ADVISORY_SAVED_PATH = "/opt/aops/cve/advisory_download"
TIMED_TASK_CONFIG_PATH = "/etc/aops/apollo_crontab.yml"


EXECUTE_REPO_SET = '/manage/vulnerability/repo/set'
EXECUTE_CVE_FIX = '/manage/vulnerability/cve/fix'
EXECUTE_CVE_SCAN = '/manage/vulnerability/cve/scan'
EXECUTE_CVE_ROLLBACK = "/manage/vulnerability/cve/rollback"

VUL_CVE_UNFIXED_PACKAGES = "/vulnerability/cve/unfixed/packages/get"
VUL_CVE_FIXED_PACKAGES = "/vulnerability/cve/fixed/packages/get"
VUL_CVE_PACKAGES_HOST = "/vulnerability/cve/packages/host/get"
VUL_TASK_CVE_RPM_HOST = "/vulnerability/task/cve/rpm/host/get"
