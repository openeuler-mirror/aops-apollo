#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
import threading
from time import time
from typing import List

from sqlalchemy.exc import SQLAlchemyError
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_INSERT_ERROR,
    NO_DATA,
    DATABASE_UPDATE_ERROR,
    SUCCEED,
    SERVER_ERROR,
)

from apollo.conf.constant import HostStatus, TaskStatus
from apollo.database.table import (
    CveHostAssociation,
    CveAffectedPkgs,
    Host,
)
from apollo.database.proxy.task.base import TaskProxy


class ScanProxy(TaskProxy):
    lock = threading.Lock()

    def update_host_scan_status(self, status: str, host_list: List[int], username: str = None) -> int:
        """
        When the host need to be scanned, init the status to 'scanning',
        and update the last scan time to current time.
        Notice, if one host id doesn't exist, all hosts will not be scanned
        Args:
            status(str): init or finish
            host_list (list): host id list, if empty, scan all hosts
            username (str): user name
        Returns:
            int: status code
        """
        try:
            status_code = self._update_host_scan(update_type=status, host_list=host_list, username=username)
            self.session.commit()
            LOGGER.debug("Finished init host scan status.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Init host scan status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _query_unaffected_cve(self, os_version: str, installed_packages: List[str]) -> list:
        """
        query CVE information which has no effect on the version

        Args:
            os_version(str): OS version
            installed_packages(list): Scanned installed packages information,
                e.g: ["pkg1", "pkg2", "pkg3"]

        Returns:
            list: list of cve info

        """
        installed_packages_cve = (
            self.session.query(CveAffectedPkgs)
            .filter(
                CveAffectedPkgs.os_version == os_version,
                CveAffectedPkgs.package.in_(installed_packages),
                CveAffectedPkgs.affected == False,
            )
            .all()
        )
        return installed_packages_cve

    def save_cve_scan_result(self, task_info: dict) -> int:
        """
        Save cve scan result to database.
        Args:
            task_info (dict): task info, e.g.
                {
                    "task_id": "string",
                    "host_id": "string",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "string",
                    "os_version": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "installed_packages": [
                        {
                            "name": "string",
                            "version": true
                        }
                    ],
                    "unfixed_cves":[
                        {
                            "cve_id": "CVE-2023-1513",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "available_rpm":"kernel-4.19.90-2304.1.0.0196.oe1.x86_64",
                            "support_way":"hotpatch/coldpatch/none"
                        }
                    ],
                    "fixed_cves": [
                        {
                            "cve_id": "CVE-2022-4904",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "fix_way": "hotpatch/coldpatch",
                            "hp_status": "ACCEPTED/ACTIVED"
                        }
                    ],
                    "reboot": true/false
                }
        Returns:
            int: status code
        """
        try:
            status = task_info["status"]
            if status == TaskStatus.SUCCEED:
                self._save_cve_scan_result(task_info)
            else:
                LOGGER.info(f"scan result failed with status {status}.")

            status_code = self._update_host_scan("finish", [task_info["host_id"]], task_info.get("reboot"))
            self.session.commit()
            LOGGER.debug("Finish saving scan result.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Save cve scan result failed.")
            return DATABASE_INSERT_ERROR

    def _save_cve_scan_result(self, task_info: dict):
        """
        Save cve scan result to database.
        Args:
            task_info (dict): task info, e.g.
                {
                    "task_id": "string",
                    "host_id": "string",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "string",
                    "os_version": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "installed_packages": [
                        {
                            "name": "string",
                            "version": true
                        }
                    ],
                    "unfixed_cves":[
                        {
                            "cve_id": "CVE-2023-1513",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "available_rpm":"kernel-4.19.90-2304.1.0.0196.oe1.x86_64",
                            "support_way":"hotpatch/coldpatch/none"
                        }
                    ],
                    "fixed_cves": [
                        {
                            "cve_id": "CVE-2022-4904",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "fix_way": "hotpatch/coldpatch",
                            "hp_status": "ACCEPTED/ACTIVED"
                        }
                    ],
                }
        """

        host_id = task_info["host_id"]
        installed_packages = [package["name"] for package in task_info["installed_packages"]]
        os_version = task_info["os_version"]

        waiting_to_save_cve_info = []

        for unaffected_cve in self._query_unaffected_cve(os_version, installed_packages):
            waiting_to_save_cve_info.append(
                {
                    "cve_id": unaffected_cve.cve_id,
                    "host_id": host_id,
                    "affected": False,
                }
            )

        for unfixed_vulnerability_info in task_info.get("unfixed_cves"):
            waiting_to_save_cve_info.append(
                {
                    "cve_id": unfixed_vulnerability_info.get("cve_id"),
                    "host_id": host_id,
                    "affected": True,
                    "fixed": False,
                    "support_way": unfixed_vulnerability_info.get("support_way") or None,
                    "installed_rpm": unfixed_vulnerability_info.get("installed_rpm") or None,
                    "available_rpm": unfixed_vulnerability_info.get("available_rpm") or None,
                }
            )

        for fixed_vulnerability_info in task_info.get("fixed_cves", []):
            waiting_to_save_cve_info.append(
                {
                    "cve_id": fixed_vulnerability_info.get("cve_id"),
                    "host_id": host_id,
                    "affected": True,
                    "fixed": True,
                    "fixed_way": fixed_vulnerability_info.get("fix_way"),
                    "installed_rpm": fixed_vulnerability_info.get("installed_rpm"),
                    "hp_status": fixed_vulnerability_info.get("hp_status"),
                }
            )
        with self.lock:
            self.session.query(CveHostAssociation).filter(CveHostAssociation.host_id == host_id).delete(
                synchronize_session=False
            )
            self.session.commit()

        self.session.bulk_insert_mappings(CveHostAssociation, waiting_to_save_cve_info)

    def _get_unaffected_cve(self, cves: list, os_version: str) -> list:
        """
        Get the unaffected CVEs.
        Args:
            cves (list): CVE list, e.g.
                ["CVE-1999-20304", "CVE-1999-20303", "CVE-1999-20301"]
            os_version(str): os version, e.g. "openEuler-22.03-LTS"

        Returns:
            list: unaffected CVEs
        """
        os_unaffected_cve_list = self._get_os_unaffected_cve(os_version)

        unaffected_cve_list = []
        for cve in cves:
            if cve in os_unaffected_cve_list:
                unaffected_cve_list.append(cve)

        return unaffected_cve_list

    def _get_os_unaffected_cve(self, os_version: str) -> list:
        """
        Query the unaffected cves under the os.
        Args:
            os_version(str):e.g. "openEuler-22.03-LTS"

        Returns:
            list: CVE list, e.g.
                ['CVE-2018-16301', 'CVE-2019-10301', 'CVE-2019-11301']
        """
        cves_list_query = (
            self.session.query(CveAffectedPkgs.cve_id)
            .filter(CveAffectedPkgs.os_version == os_version, CveAffectedPkgs.affected == 0)
            .all()
        )

        cve_list = []
        if cves_list_query:
            cve_list = [cve[0] for cve in cves_list_query]

        return cve_list

    def _update_host_scan(
        self, update_type: str, host_list: List[int], reboot: bool = False, username: str = None
    ) -> int:
        """
        Update hosts scan status and last_scan time
        Args:
            update_type (str): 'init' or 'finish'
            host_list (list): host id list
            reboot (bool): host restart status
            username (str): user name
        Returns:

        """
        if update_type == "init":
            update_dict = {Host.status: HostStatus.SCANNING, Host.last_scan: int(time())}
        elif update_type == "finish":
            update_dict = {Host.status: HostStatus.DONE, Host.reboot: reboot}
        else:
            LOGGER.error(
                "Given host scan update type '%s' is not in default type list ['init', 'finish']." % update_type
            )
            return SERVER_ERROR

        host_scan_query = self._query_scan_status_and_time(host_list, username)
        succeed_list = [row.host_id for row in host_scan_query]
        fail_list = set(host_list) - set(succeed_list)
        if fail_list:
            LOGGER.debug("No data found when setting the status of host: %s." % fail_list)
            if update_type == "init":
                return NO_DATA

        # update() is not applicable to 'in_' method without synchronize_session=False
        host_scan_query.update(update_dict, synchronize_session=False)
        return SUCCEED

    def _query_scan_status_and_time(self, host_list: List[int], username: str):
        """
        query host status and last_scan data of specific user
        Args:
            host_list (list): host id list, when empty, query all hosts
            username (str/None): user name
        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = set()
        if host_list:
            filters.add(Host.host_id.in_(host_list))
        if username:
            filters.add(Host.user == username)

        hosts_status_query = self.session.query(Host).filter(*filters)
        return hosts_status_query
