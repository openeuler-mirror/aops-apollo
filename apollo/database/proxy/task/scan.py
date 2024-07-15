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
from typing import List

from sqlalchemy.exc import SQLAlchemyError
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import DATABASE_INSERT_ERROR, SUCCEED

from apollo.conf.constant import TaskStatus
from apollo.database.proxy.task.base import TaskProxy
from apollo.database.table import CveAffectedPkgs, CveHostAssociation


class ScanProxy(TaskProxy):
    lock = threading.Lock()

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

    def save_cve_scan_result(self, task_info: dict) -> str:
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
            str: status code
        """
        try:
            status = task_info["status"]
            if status == TaskStatus.SUCCEED:
                self._save_cve_scan_result(task_info)
            else:
                LOGGER.info(f"scan result failed with status {status}.")

            self.session.commit()
            LOGGER.debug("Finish saving scan result.")
            return SUCCEED
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
        cluster_id = task_info.get("cluster_id")
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
                    "cluster_id": cluster_id,
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
                    "cluster_id": cluster_id,
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
