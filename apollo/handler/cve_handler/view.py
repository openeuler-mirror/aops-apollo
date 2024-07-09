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
Description: Handle about cve related operation
"""
import copy
import glob
import os
import shutil
import time
from collections import defaultdict
from typing import List, Optional, Tuple
from urllib.parse import urlencode

from flask import g
from vulcanus.conf.constant import HOSTS_FILTER
from vulcanus.database.helper import judge_return_code
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    SUCCEED,
    DATABASE_INSERT_ERROR,
    WRONG_FILE_FORMAT,
    NO_DATA,
    SERVER_ERROR,
    PARAM_ERROR,
)
from vulcanus.restful.response import BaseResponse

from apollo.cron.notification import EmailNoticeManager
from apollo.conf import configuration, cache
from apollo.conf.constant import FILE_UPLOAD_PATH
from apollo.database.proxy.cve import CveProxy, CveMysqlProxy
from apollo.database.proxy.host import HostProxy
from apollo.function.customize_exception import ParseAdvisoryError
from apollo.function.schema.cve import (
    CveBinaryPackageSchema,
    GetCveListSchema,
    GetCveInfoSchema,
    GetCveHostsSchema,
    GetCveTaskHostSchema,
    GetGetCvePackageHostSchema,
    ExportCveExcelSchema,
)
from apollo.function.utils import make_download_response, query_user_hosts
from apollo.handler.cve_handler.manager.compress_manager import unzip
from apollo.handler.cve_handler.manager.parse_advisory import parse_security_advisory
from apollo.handler.cve_handler.manager.parse_unaffected import parse_unaffected_cve


class VulGetCveOverview(BaseResponse):
    """
    Restful interface for getting CVE's overview info
    """

    @BaseResponse.handle(proxy=CveMysqlProxy)
    def get(self, callback: CveMysqlProxy, **params):
        """
        Get overview of cve severity

        Args:

        Returns:
            dict: response body

        """
        status_code, result = callback.get_cve_overview(query_user_hosts())
        return self.response(code=status_code, data=result)


class VulGetCveList(BaseResponse):
    """
    Restful interface for getting cve list of all hosts
    """

    @BaseResponse.handle(schema=GetCveListSchema, proxy=CveProxy)
    def post(self, callback: CveProxy, **params):
        """
        Get cve list of all hosts

        Args:
            sort (str): can be chosen from cve_id, publish_time, cvss_score, hosts_num (optional)
            direction (str): asc or desc, default asc (optional)
            page (int): current page in front (optional)
            per_page (int): cve number of each page (optional)
            filter (dict): filter condition (optional)

        Returns:
            dict: response body

        """
        result = {"total_count": 0, "total_page": 0, "result": []}
        params["host_list"] = query_user_hosts()
        status_code, result = callback.get_cve_list(params)
        return self.response(code=status_code, data=result)


class VulGetCveInfo(BaseResponse):
    """
    Restful interface for getting detailed info of a cve
    """

    @BaseResponse.handle(schema=GetCveInfoSchema, proxy=CveProxy)
    def get(self, callback: CveProxy, **params):
        """
        Get detailed info of a cve

        Args:
            cve_id (str): cve id

        Returns:
            dict: response body

        """
        status_code, result = callback.get_cve_info(params)
        return self.response(code=status_code, data=result)


class VulGetCveHosts(BaseResponse):
    """
    Restful interface for getting hosts info of a cve
    """

    @staticmethod
    def paginate_data(data: List[dict], per_page: int, page: int) -> Tuple[int, int, List[dict]]:
        """
        Paginates the data and returns information for the specified page.

        Args:
            data: A list of dictionaries representing the original data.
            per_page: The number of items to display per page.
            page: The requested page number.

        Returns:
            A tuple containing the total number of items, total number of pages, and the data for the specified page.
        """
        total_count = len(data)
        total_page = (total_count + per_page - 1) // per_page
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total_count)
        paginated_data = data[start_idx:end_idx]
        return total_count, total_page, paginated_data

    def _query_host_info(self, host_list: List[str], filters: Optional[dict] = None) -> list:
        """Queries host information for the specified list of hosts.

        Args:
            host_list(List[str]): host id list
            filters(Optional[dict]): Optional filters to apply to the query.

        Returns:
            list: host info list
        """
        if not filters:
            filters = {}
        filters.pop("fixed", None)
        query_fields = ["host_id", "host_ip", "host_name", "last_scan", "repo_id", "host_group_name", "cluster_id"]
        return query_user_hosts(host_list=host_list, fields=query_fields, **filters)

    def _handle(self, params: dict, proxy: CveMysqlProxy) -> Tuple[str, dict]:
        """
        Handles the query for CVE-related host information.
        """
        # 1. Query host ids related to the CVE ID
        status_code, query_rows = proxy.query_host_id_list_related_to_cve(
            params.get("cve_id"), params.get("filter", {}).get("fixed", False)
        )
        if status_code != SUCCEED:
            return status_code, {}
        host_list = [row.host_id for row in query_rows]
        if not host_list:
            return status_code, {"total_count": 0, "total_page": 0, "result": []}

        # 2. Query all host info
        host_info_list = self._query_host_info(host_list, params.get("filter"))

        # 3. Sort all data based on sorting rules
        user_clusters_info = cache.get_user_clusters()
        for host in host_info_list:
            host["cluster_name"] = user_clusters_info.get(host["cluster_id"])
        sort_field = params.get("sort")
        direction = params.get("direction") == "desc"
        if sort_field:
            host_info_list = sorted(host_info_list, key=lambda host: host[sort_field], reverse=not direction)

        # 4. Paginate the data
        total_count, total_page, paginated_data = self.paginate_data(
            host_info_list, params.get("per_page"), params.get("page")
        )
        # 5. Return the target data
        result = {"total_count": total_count, "total_page": total_page, "result": paginated_data}
        return SUCCEED, result

    @BaseResponse.handle(schema=GetCveHostsSchema, proxy=CveMysqlProxy)
    def post(self, callback: CveMysqlProxy, **params):
        """
        Get hosts info of a cve

        Args:
            cve_id (str): cve id
            sort (str): can be chose from last_scan
            direction (str): asc or desc, default asc (optional)
            page (int): current page in front (optional)
            per_page (int): host number of each page (optional)
            filter (dict): filter condition

        Returns:
            dict: response body

        """
        # Get all host id related to cve
        status_code, result = self._handle(params, callback)
        return self.response(code=status_code, data=result)


class VulGetCveTaskHost(BaseResponse):
    """
    Restful interface for getting each CVE's hosts' basic info (id, ip, name)
    """

    def _query_host_info(self, host_list: List[str]) -> dict:
        """Queries host information for the specified list of hosts.

        Args:
            host_list(list): host id list

        Returns:
            The response data obtained from the query.
        """
        result = {}
        host_info_list = query_user_hosts(host_list=host_list, fields=["host_id", "host_ip", "host_name", "cluster_id"])

        if len(host_info_list) != len(host_list):
            return PARAM_ERROR, result

        for host in host_info_list:
            result[host.get("host_id")] = dict(
                host_id=host.get("host_id"),
                host_ip=host.get("host_ip"),
                host_name=host.get("host_name"),
                cluster_id=host.get("cluster_id"),
            )

        return result

    def _get_cve_task_hosts_for_hp_remove(self, cve_task_hosts_rows, cluster_info) -> dict:
        """
        get cve task hosts data for previous remove_hp task. This is a temporary function ,
        going to be changed in 10.30 given hotpatch of cve

        Args:
            cve_task_hosts_rows (sqlalchemy.orm.query.Query): rows of cve host pkg info

        Returns:
            dict: each CVE's host info  e.g.
                {
                    "CVE-2023-25180": {
                        "package": "glibc,kernel",
                        "hosts": [{
                            "host_id": 1100,
                            "host_ip": "172.168.120.151",
                            "host_name": "host2_12006",
                            "hotpatch": True // The param only exist if input fixed is True
                        }]
                    }
                }
        """
        cve_host_dict = defaultdict(dict)
        host_id_list = set()
        # cve_host_dict: {"cve-2022-1111": {host_id1: True, host_id2: False}}
        for row in cve_task_hosts_rows:
            pkg_fixed_by_hp = True if row.fixed_way == "hotpatch" else False
            host_id_list.add(row.host_id)
            if row.host_id not in cve_host_dict[row.cve_id]:
                cve_host_dict[row.cve_id][row.host_id] = pkg_fixed_by_hp
            else:
                cve_host_dict[row.cve_id][row.host_id] |= pkg_fixed_by_hp

        # get host info
        # host_info_dict: {host_id1: {"host_name": "name1", "host_ip": "1.1.1.1"}
        host_info_dict = self._query_host_info(list(host_id_list))
        for host_id, info in host_info_dict.items():
            info["cluster_name"] = cluster_info.get(info.get("cluster_id"))

        # query cve affected source package
        queried_cve_list = list(cve_host_dict.keys())
        cve_pkg_dict = self.proxy._get_cve_source_pkg(queried_cve_list)

        result = {}
        for cve_id, host_hp_info in cve_host_dict.items():
            host_info_list = []
            for host_id, cve_fixed_by_hp in host_hp_info.items():
                host_info = copy.deepcopy(host_info_dict[host_id])
                host_info["hotpatch"] = cve_fixed_by_hp
                host_info_list.append(host_info)
            result[cve_id] = {"package": cve_pkg_dict[cve_id], "hosts": host_info_list}

        return SUCCEED, result

    def _get_cve_task_hosts_for_cve_fix(
        self, cve_id_list: list, cve_info_list: list, cve_task_hosts_rows, cluster_info
    ) -> dict:
        """
        get cve task hosts data for previous cve_fix task.
        Args:
            cve_id_list (list): list of cve id
            cve_info_list (list): list of cve info.  e.g.
                [{
                    "cve_id": "CVE-2023-1",
                    "rpms": [{
                        "installed_rpm": "pkg1",
                        "available_rpm": "pkg1-1",
                        "fix_way":"hotpatch"
                    }]
                },
                {
                    "cve_id": "CVE-2023-2",
                    "rpms": []
                }]
            cve_task_hosts_rows (sqlalchemy.orm.query.Query): rows of cve host pkg info

        Returns:
            dict: each CVE's host info  e.g.
                {
                    "CVE-2023-25180": {
                        "package": "glibc,kernel",
                        "hosts": [{
                            "host_id": 1100,
                            "host_ip": "172.168.120.151",
                            "host_name": "host2_12006"
                        }]
                    }
                }
        """
        # query cve affected source pacakge
        cve_pkg_dict = self.proxy._get_cve_source_pkg(cve_id_list)

        # get host info
        host_id_list = set()
        for row in cve_task_hosts_rows:
            host_id_list.add(row.host_id)
        # host_info_dict: {host_id1: {"host_name": "name1", "host_ip": "1.1.1.1"}
        host_info_dict = self._query_host_info(list(host_id_list))

        for host_id, info in host_info_dict.items():
            info["cluster_name"] = cluster_info.get(info.get("cluster_id"), {})

        result = {}
        for cve_info in cve_info_list:
            cve_id = cve_info["cve_id"]
            if cve_info.get("rpms"):
                host_id_set = set()
                for rpm_info in cve_info["rpms"]:
                    filtered_rows = filter(
                        lambda cve_host_rpm: cve_host_rpm.cve_id == cve_id
                        and cve_host_rpm.installed_rpm == rpm_info["installed_rpm"]
                        and cve_host_rpm.available_rpm == rpm_info["available_rpm"],
                        cve_task_hosts_rows,
                    )
                    host_id_set |= set([row.host_id for row in filtered_rows])
                affected_host_id = list(host_id_set)
            else:
                filtered_rows = filter(lambda cve_host_rpm: cve_host_rpm.cve_id == cve_id, cve_task_hosts_rows)
                affected_host_id = list(set([row.host_id for row in filtered_rows]))

            host_info_list = []
            for host_id in affected_host_id:
                host_info_list.append(host_info_dict[host_id])

            result[cve_id] = {"package": cve_pkg_dict[cve_id], "hosts": host_info_list}

        return SUCCEED, result

    def _handle(self, data):
        """
        handle function
        """
        result = {}
        cluster_info = cache.get_user_clusters()
        data["host_list"] = query_user_hosts(data.get("host_list", []))
        status_code, query_rows = self.proxy.get_cve_task_hosts(data)
        if status_code != SUCCEED:
            LOGGER.error("Failed to query cve task hosts.")
            return status_code, result

        cve_info_list = data["cve_list"]
        cve_id_list = [cve_info["cve_id"] for cve_info in cve_info_list]
        if data["fixed"]:
            status_code, result = self._get_cve_task_hosts_for_hp_remove(query_rows, cluster_info)
        else:
            status_code, result = self._get_cve_task_hosts_for_cve_fix(
                cve_id_list, cve_info_list, query_rows, cluster_info
            )

        if status_code != SUCCEED:
            return status_code, result

        succeed_list = list(result.keys())
        fail_list = list(set(cve_id_list) - set(succeed_list))
        if fail_list:
            LOGGER.debug("No data found when getting the task hosts of cve: %s." % fail_list)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, NO_DATA)
        return status_code, result

    @BaseResponse.handle(schema=GetCveTaskHostSchema, proxy=CveMysqlProxy)
    def post(self, callback: CveMysqlProxy, **params):
        """
        Get basic info of hosts which have specific cve

        Args:
            callback: CveMysqlProxy
            params: dict of params.  e.g.
                {
                    "username": "admin",
                    "cve_list": [
                        {
                            "cve_id": "CVE-2023-25180",
                            "rpms":[{
                              "installed_rpm":"pkg1",
                              "available_rpm": "pkg1-1",
                              "fix_way":"hotpatch"
                            }]
                        }
                    ],
                    "fixed":true
                }

        Returns:
            dict: response body

        """
        self.proxy: CveMysqlProxy = callback
        status_code, result = self._handle(params)
        return self.response(code=status_code, data=result)


class VulUploadAdvisory(BaseResponse):
    """
    Restful interface for importing security advisory xml (compressed files or single file)
    """

    def _handle(self, proxy):
        """
        Handle uploading security advisory xml files
        Returns:
            int: status code
        """
        save_path = FILE_UPLOAD_PATH
        status, username, file_name = self.verify_upload_request(save_path)

        if status != SUCCEED:
            return status

        file_path = os.path.join(save_path, username, file_name)

        suffix = file_name.split('.')[-1]
        if suffix == "xml":
            status_code = self._save_single_advisory(proxy, file_path)
        elif suffix == "zip":
            folder_path = unzip(file_path)
            if not folder_path:
                LOGGER.error("Unzip file '%s' failed." % file_name)
                return WRONG_FILE_FORMAT
            status_code = self._save_compressed_advisories(proxy, folder_path)
        else:
            status_code = WRONG_FILE_FORMAT
        return status_code

    @staticmethod
    def _save_single_advisory(proxy, file_path):
        file_name = os.path.basename(file_path)
        try:
            security_cvrf_info = parse_security_advisory(file_path)
            os.remove(file_path)
            if not all([security_cvrf_info.cve_rows, security_cvrf_info.cve_pkg_rows, security_cvrf_info.cve_pkg_docs]):
                return WRONG_FILE_FORMAT
        except (KeyError, ParseAdvisoryError) as error:
            os.remove(file_path)
            LOGGER.error("Some error occurred when parsing advisory '%s'." % file_name)
            LOGGER.error(error)
            return WRONG_FILE_FORMAT

        status_code = proxy.save_security_advisory(file_name, security_cvrf_info)

        return status_code

    @staticmethod
    def _save_compressed_advisories(proxy, folder_path):
        """
        save advisories into database
        Args:
            proxy (CveProxy): connected CveProxy object
            folder_path (str): decompressed folder
        Returns:
            int

        Raises:
            ParseXmlError
        """
        file_path_list = glob.glob(folder_path + '/*')

        succeed_list = []
        fail_list = []
        for file_path in file_path_list:
            file_name = os.path.basename(file_path)
            suffix = file_name.split('.')[-1]
            if suffix != "xml":
                shutil.rmtree(folder_path)
                return WRONG_FILE_FORMAT
            try:
                security_cvrf_info = parse_security_advisory(file_path)
                if not all(
                    [security_cvrf_info.cve_rows, security_cvrf_info.cve_pkg_rows, security_cvrf_info.cve_pkg_docs]
                ):
                    shutil.rmtree(folder_path)
                    return WRONG_FILE_FORMAT
            except (KeyError, ParseAdvisoryError) as error:
                fail_list.append(file_name)
                LOGGER.error("Some error occurred when parsing advisory '%s'." % file_name)
                LOGGER.error(error)
                continue
            except IsADirectoryError as error:
                fail_list.append(file_name)
                LOGGER.error("Folder %s cannot be parsed as an advisory." % file_name)
                LOGGER.error(error)
                continue
            # elasticsearch need 1 second to update doc
            status_code = proxy.save_security_advisory(file_name, security_cvrf_info)
            if status_code != SUCCEED:
                fail_list.append(file_name)
            else:
                succeed_list.append(file_name)
        shutil.rmtree(folder_path)

        if fail_list:
            fail_list_str = ','.join(fail_list)
            LOGGER.warning("The advisory '%s' insert failed." % fail_list_str)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, DATABASE_INSERT_ERROR)
        return status_code

    @BaseResponse.handle(proxy=CveProxy)
    def post(self, callback: CveProxy, **params):
        """
        Get rar/zip/rar compressed package or single xml file, decompress and insert data
        into database

        Returns:
            dict: response body
        """
        return self.response(code=self._handle(callback))


class VulUploadUnaffected(BaseResponse):
    """
    Restful interface for importing unaffected cve xml (compressed files or single file)
    """

    def _handle(self, proxy):
        """
        Handle uploading unaffected cve xml files
        Returns:
            int: status code
        """
        save_path = FILE_UPLOAD_PATH
        status, username, file_name = self.verify_upload_request(save_path)

        if status != SUCCEED:
            return status

        file_path = os.path.join(save_path, username, file_name)

        suffix = file_name.split('.')[-1]
        if suffix == "xml":
            status_code = self._save_unaffected_cve(proxy, file_path)
        elif suffix == "zip":
            folder_path = unzip(file_path)
            if not folder_path:
                LOGGER.error("Unzip file '%s' failed." % file_name)
                return WRONG_FILE_FORMAT
            status_code = self._save_compressed_unaffected_cve(proxy, folder_path)
        else:
            status_code = WRONG_FILE_FORMAT
        return status_code

    @staticmethod
    def _save_unaffected_cve(proxy, file_path):
        """
        Save unaffected cve advisory to mysql
        Args:
            proxy (CveProxy): connected CveProxy object
            file_path (str): unaffected cve xml file path
        Returns:
            int: status code
        """
        file_name = os.path.basename(file_path)
        try:
            cve_rows, cve_pkg_rows, doc_list = parse_unaffected_cve(file_path)
            if not all([cve_rows, cve_pkg_rows, doc_list]):
                os.remove(file_path)
                return WRONG_FILE_FORMAT
            os.remove(file_path)
        except (KeyError, ParseAdvisoryError) as error:
            os.remove(file_path)
            LOGGER.error("Some error occurred when parsing unaffected cve advisory '%s'." % file_name)
            LOGGER.error(error)
            return WRONG_FILE_FORMAT

        status_code = proxy.save_unaffected_cve(file_name, cve_rows, cve_pkg_rows, doc_list)
        return status_code

    @staticmethod
    def _save_compressed_unaffected_cve(proxy, folder_path):
        """
        save unaffected into database
        Args:
            proxy (CveProxy): connected CveProxy object
            folder_path (str): decompressed folder
        Returns:
            int

        Raises:
            ParseXmlError
        """
        file_path_list = glob.glob(folder_path + '/*')

        succeed_list = []
        fail_list = []
        for file_path in file_path_list:
            file_name = os.path.basename(file_path)
            suffix = file_name.split('.')[-1]
            if suffix != "xml":
                shutil.rmtree(folder_path)
                return WRONG_FILE_FORMAT
            try:
                cve_rows, cve_pkg_rows, doc_list = parse_unaffected_cve(file_path)
                if not all([cve_rows, cve_pkg_rows, doc_list]):
                    shutil.rmtree(folder_path)
                    return WRONG_FILE_FORMAT
            except (KeyError, ParseAdvisoryError) as error:
                fail_list.append(file_name)
                LOGGER.error("Some error occurred when parsing unaffected cve advisory '%s'." % file_name)
                LOGGER.error(error)
                continue
            except IsADirectoryError as error:
                fail_list.append(file_name)
                LOGGER.error("Folder %s cannot be parsed as an unaffected." % file_name)
                LOGGER.error(error)
                continue
            status_code = proxy.save_unaffected_cve(file_name, cve_rows, cve_pkg_rows, doc_list)
            if status_code != SUCCEED:
                fail_list.append(file_name)
            else:
                succeed_list.append(file_name)
        shutil.rmtree(folder_path)

        if fail_list:
            fail_list_str = ','.join(fail_list)
            LOGGER.warning("The unaffected cve '%s' insert failed." % fail_list_str)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, DATABASE_INSERT_ERROR)
        return status_code

    @BaseResponse.handle(proxy=CveProxy)
    def post(self, callback=CveProxy, **params):
        """
        Get rar/zip/rar compressed package or single xml file, decompress and insert data
        into database

        Returns:
            dict: response body
        """
        return self.response(self._handle(callback))


class VulExportExcel(BaseResponse):
    """
    Restful interface for export cve to excel
    """

    @staticmethod
    def _handle(proxy, args):
        """
        Handle export csv
        Returns:
            dict: result. e.g.
                {
                    "status": status,
                    "fileinfo": {
                        "filename": filename,
                        "filepath": "filepath"
                        }
                }
        """

        if not os.path.exists(CSV_SAVED_PATH):
            os.makedirs(CSV_SAVED_PATH)
        filepath = os.path.join(CSV_SAVED_PATH, args["username"])
        if os.path.exists(filepath):
            shutil.rmtree(filepath)
        os.mkdir(filepath)

        status, cve_body = proxy.query_host_name_and_related_cves(args["host_list"], args["username"])
        result = {}
        if status != SUCCEED:
            result["status"] = status
            return result

        filename = "host_cve_info.csv"
        csv_head = ["host_ip", "host_name", "cve_id", "installed_rpm", "available_rpm", "support_way", "fixed_way"]

        export_csv(cve_body, os.path.join(filepath, filename), csv_head)

        if len(os.listdir(filepath)) == 0:
            result["status"] = NO_DATA
            return result
        if len(os.listdir(filepath)) > FILE_NUMBER:
            zip_filename, zip_save_path = compress_cve(filepath, "host.zip")
            if zip_filename and zip_save_path:
                filename = zip_filename
                filepath = zip_save_path
            else:
                result["status"] = SERVER_ERROR
                return result
        result["status"] = SUCCEED
        file_info = {"filename": filename, "filepath": filepath}
        result["fileinfo"] = file_info
        return result

    @BaseResponse.handle(proxy=CveProxy, schema=ExportCveExcelSchema)
    def post(self, callback: CveProxy, **params):
        """
        Get rar/zip/rar compressed package or single xml file, decompress and insert data into database

        Returns:
            dict: response body
        """
        result = self._handle(callback, params)
        if result.get("status") == SUCCEED:
            fileinfo = result.get("fileinfo")
            return make_download_response(
                os.path.join(fileinfo.get("filepath"), fileinfo.get("filename")), fileinfo.get("filename")
            )
        return self.response(code=result)


class VulUnfixedCvePackage(BaseResponse):
    """
    Restful interface for get unfixed cve package
    """

    @BaseResponse.handle(proxy=CveProxy, schema=CveBinaryPackageSchema)
    def post(self, callback: CveProxy, **params):
        """
        Get unfixed cve package by host

        Returns:
            dict: response body
        """
        status_code, unfix_cve_packages = callback.get_cve_unfixed_packages(
            cve_id=params["cve_id"], host_ids=params.get("host_ids"), username=params["username"]
        )
        return self.response(code=status_code, data=unfix_cve_packages)


class VulFixedCvePackage(BaseResponse):
    """
    Restful interface for get fixed cve package
    """

    @BaseResponse.handle(proxy=CveProxy, schema=CveBinaryPackageSchema)
    def post(self, callback: CveProxy, **params):
        """
        Get fixed cve package by host

        Returns:
            dict: response body
        """
        status_code, unfix_cve_packages = callback.get_cve_fixed_packages(
            cve_id=params["cve_id"], host_ids=params.get("host_ids"), username=params["username"]
        )
        return self.response(code=status_code, data=unfix_cve_packages)


class VulGetCvePackageHost(BaseResponse):
    """
    Restful interface for get cve package host list
    """

    @BaseResponse.handle(proxy=CveProxy, schema=GetGetCvePackageHostSchema)
    def post(self, callback: CveProxy, **params):
        """
        Get cve package host list

        Args:
            cve_id (str): cve id
            package (str): binary package
            direction (str): asc or desc, default asc (optional)
            page (int): current page in front (optional)
            per_page (int): host number of each page (optional)

        Returns:
            dict: response body
        """
        status_code, hosts = callback.get_cve_packages_host(params)
        return self.response(code=status_code, data=hosts)
