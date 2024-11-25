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
EXTRA_FILE_SERVICE_PATH = "/opt/aops/scripts/file_service_support"
FILE_SAVE_PATH = "/opt/aops/file"

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


class TaskChannel:
    """
    The name of the channel pushed to redis after task execution is completed,
    and it has the same name as the task registered in celery
    """

    CVE_SCAN_TASK = 'cve_scan_task'
    CVE_FIX_TASK = 'cve_fix_task'
    REPO_SET_TASK = 'repo_set_task'
    CVE_ROLLBACK_TASK = 'cve_rollback_task'
    HOTPATCH_REMOVE_TASK = 'hotpatch_remove_task'
    CLUSTER_SYNCHRONIZE_CANCEL_TASK = 'cluster_synchronize_cancel_task'
    TIMED_SCAN_TASK = "cve_scan"
    TIMED_CORRECT_TASK = "correct_data"
    TIMED_SEND_NOTIFICATION = "send_notification"
    TIMED_DOWNLOAD_SA = "download_sa"


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
    HOTPATCH_REMOVE = "hotpatch remove"

    @staticmethod
    def attribute():
        return [TaskType.CVE_FIX, TaskType.CVE_ROLLBACK, TaskType.REPO_SET, TaskType.HOTPATCH_REMOVE]


class TaskStatus(CveHostStatus):
    pass


# route of repo related interface
VUL_REPO_IMPORT = "/vulnerabilities/repo/import"
VUL_REPO_GET = "/vulnerabilities/repo/get"
VUL_REPO_UPDATE = "/vulnerabilities/repo/update"
VUL_REPO_DELETE = "/vulnerabilities/repo/delete"
VUL_REPO_TEMPLATE_GET = "/vulnerabilities/repo/template/get"

# route of cve related interface
VUL_CVE_OVERVIEW = "/vulnerabilities/cve/overview"
VUL_CVE_LIST_GET = "/vulnerabilities/cve/list/get"
VUL_CVE_INFO_GET = "/vulnerabilities/cve/info/get"
VUL_CVE_HOST_GET = "/vulnerabilities/cve/host/get"
VUL_CVE_TASK_HOST_GET = "/vulnerabilities/cve/task/host/get"
VUL_CVE_STATUS_SET = "/vulnerabilities/cve/status/set"
VUL_CVE_UPLOAD_ADVISORY = "/vulnerabilities/cve/advisory/upload"
VUL_CVE_UPLOAD_UNAFFECTED = "/vulnerabilities/cve/unaffected/upload"
VUL_EXPORT_EXCEL = "/vulnerabilities/cve/info/export"

# route of host related interface
VUL_HOST_SCAN = "/vulnerabilities/host/scan"
VUL_HOST_STATUS_GET = "/vulnerabilities/host/status/get"
VUL_HOST_LIST_GET = "/vulnerabilities/host/list/get"
VUL_HOST_INFO_GET = "/vulnerabilities/host/info/get"
VUL_HOST_CVE_GET = "/vulnerabilities/host/cve/get"

# route of task related interface
VUL_TASK_LIST_GET = "/vulnerabilities/task/list/get"
VUL_TASK_PROGRESS_GET = "/vulnerabilities/task/progress/get"
VUL_TASK_INFO_GET = "/vulnerabilities/task/info/get"
VUL_TASK_CVE_FIX_GENERATE = "/vulnerabilities/task/cve-fix/generate"
VUL_TASK_CVE_FIX_INFO_GET = "/vulnerabilities/task/cve-fix/info/get"
VUL_TASK_HOTPATCH_REMOVE_STATUS_GET = "/vulnerabilities/task/hotpatch-remove/status/get"
VUL_TASK_CVE_FIX_RESULT_GET = "/vulnerabilities/task/cve-fix/result/get"
VUL_TASK_EXECUTE = "/vulnerabilities/task/execute"
VUL_TASK_REPO_GENERATE = "/vulnerabilities/task/repo/generate"
VUL_TASK_REPO_INFO_GET = "/vulnerabilities/task/repo/info/get"
VUL_TASK_REPO_RESULT_GET = "/vulnerabilities/task/repo/result/get"
VUL_TASK_DELETE = "/vulnerabilities/task/delete"
VUL_TASK_CVE_ROLLBACK_GENERATE = "/vulnerabilities/task/cve-rollback/generate"
VUL_TASK_CVE_ROLLBACK_RESULT_GET = "/vulnerabilities/task/cve-rollback/result/get"
VUL_TASK_CVE_ROLLBACK_INFO_GET = "/vulnerabilities/task/cve-rollback/info/get"
VUL_TASK_CVE_ROLLBACK_RPM_INFO_GET = "/vulnerabilities/task/cve-rollback/rpm/get"
VUL_TASK_HOTPATCH_REMOVE_GENERATE = "/vulnerabilities/task/hotpatch-remove/generate"
VUL_TASK_CVE_FIX_RPM_INFO_GET = "/vulnerabilities/task/cve-fix/rpm/get"
VUL_TASK_HOTPATCH_REMOVE_INFO_GET = "/vulnerabilities/task/hotpatch-remove/info/get"
VUL_TASK_HOTPATCH_REMOVE_RESULT_GET = "/vulnerabilities/task/hotpatch-remove/result/get"
VUL_TASK_HOTPATCH_REMOVE_PROGRESS_GET = "/vulnerabilities/task/hotpatch-remove/progress/get"

# route of callback
VUL_TASK_CVE_FIX_CALLBACK = "/vulnerabilities/task/callback/cve/fix"
VUL_TASK_CVE_ROLLBACK_CALLBACK = "/vulnerabilities/task/callback/cve/rollback"
VUL_TASK_REPO_SET_CALLBACK = "/vulnerabilities/task/callback/repo/set"
VUL_TASK_CVE_SCAN_CALLBACK = "/vulnerabilities/task/callback/cve/scan"
VUL_TASK_HOTPATCH_REMOVE_CALLBACK = "/vulnerabilities/task/callback/hotpatch-remove"
VUL_TASK_CVE_SCAN_NOTICE = "/vulnerabilities/task/callback/cve/scan/notice"
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

EXECUTE_REPO_SET = '/manage/vulnerabilities/repo/set'
EXECUTE_CVE_FIX = '/manage/vulnerabilities/cve/fix'
EXECUTE_CVE_ROLLBACK = '/manage/vulnerabilities/cve/rollback'
EXECUTE_CVE_SCAN = '/manage/vulnerabilities/cve/scan'
EXECUTE_HOTPATCH_REMOVE = "/manage/vulnerabilities/cve/hotpatch-remove"
HOST_STATUS_GET = "/manage/host/status/get"

VUL_CVE_UNFIXED_PACKAGES = "/vulnerabilities/cve/unfixed/packages/get"
VUL_CVE_FIXED_PACKAGES = "/vulnerabilities/cve/fixed/packages/get"
VUL_CVE_PACKAGES_HOST = "/vulnerabilities/cve/packages/host/get"
VUL_GET_TASK_HOST = "/vulnerabilities/task/host/get"
VUL_DOWNLOAD_FILE = "/vulnerabilities/file/download"
VUL_GET_FILE_LIST = "/vulnerabilities/file/list/get"
VUL_GET_AI_CVES = "/vulnerabilities/cves"
VUL_GET_AI_RECOMMENDED_CVES = "/vulnerabilities/cves/recommended"
