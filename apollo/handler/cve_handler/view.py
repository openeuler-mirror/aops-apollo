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
import uuid
from collections import defaultdict
from typing import List, Optional

from flask import g, request
from werkzeug.utils import secure_filename
from vulcanus.database.helper import judge_return_code
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_INSERT_ERROR,
    NO_DATA,
    PARAM_ERROR,
    SERVER_ERROR,
    SUCCEED,
    WRONG_FILE_FORMAT,
)
from vulcanus.restful.response import BaseResponse

from apollo.conf import cache
from apollo.conf.constant import FILE_UPLOAD_PATH
from apollo.cron.notification import EmailNoticeManager
from apollo.database.proxy.cve import CveMysqlProxy, CveProxy
from apollo.database.proxy.host import HostProxy
from apollo.function.customize_exception import ParseAdvisoryError
from apollo.function.schema.cve import (
    CveBinaryPackageSchema,
    ExportCveExcelSchema,
    GetCveHostsSchema,
    GetCveInfoSchema,
    GetCveListSchema,
    GetCveTaskHostSchema,
    GetGetCvePackageHostSchema,
)
from apollo.function.utils import make_download_response, query_user_hosts, paginate_data
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

    def _query_host_info(self, host_list: List[str], filters: Optional[dict] = None):
        """Queries host information for the specified list of hosts.

        Args:
            filters(Optional[dict]): Optional filters to apply to the query.

        Returns:
            The response data obtained from the query.
        """
        if not filters:
            filters = {}
        filters.pop("fixed", None)
        query_fields = ["host_id", "host_ip", "host_name", "last_scan", "repo_id", "host_group_name", "cluster_id"]
        return query_user_hosts(host_list=host_list, fields=query_fields, **filters)

    def _handle(self, params, proxy: CveMysqlProxy):
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
        # 5. Paginate the data
        page = params.get("page")
        per_page = params.get("per_page")

        if page and per_page:
            total_count, total_page, paginated_data = paginate_data(host_info_list, per_page, page)
        else:
            total_count = len(host_info_list)
            total_page = 1
            paginated_data = host_info_list
        # 6. Return the target data
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

    def _query_host_info(self, host_list):
        """"""

        result = {}
        query_fields = ["host_id", "host_ip", "host_name", "cluster_id"]
        host_info_list = query_user_hosts(host_list, query_fields)

        if len(host_info_list) != len(host_list):
            return PARAM_ERROR, result

        for host in host_info_list:
            result[host.get("host_id")] = dict(
                host_id=host.get("host_id"),
                host_ip=host.get("host_ip"),
                host_name=host.get("host_name"),
                cluster_id=host.get("cluster_id"),
            )

        return SUCCEED, result

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
        status, host_info_dict = self._query_host_info(list(host_id_list))
        if status != SUCCEED:
            LOGGER.error("Failed to query host information in task")
            return status, {}

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
        status, host_info_dict = self._query_host_info(list(host_id_list))
        if status != SUCCEED:
            LOGGER.error("Failed to query host information in task")
            return status, {}

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


class FileUpload:
    @classmethod
    def _upload_file(cls, save_path, file_key="file"):
        """
        upload file to save_path
        Args:
            save_path (str): path the file to be saved
            file_key (str): body key for the file

        Returns:
            int: verify status code
            str: file_path
            str: file_name
        """

        file_name = ""
        file = request.files.get(file_key)
        if file is None or not file.filename:
            return PARAM_ERROR, "", file_name
        username = g.username
        filename = secure_filename(file.filename)
        file_name = str(uuid.uuid4()) + "." + filename.rsplit('.', 1)[-1]
        if not os.path.exists(os.path.join(save_path, username)):
            os.makedirs(os.path.join(save_path, username))
        file_path = os.path.join(save_path, username, file_name)
        file.save(file_path)
        return SUCCEED, file_path, file_name


class VulUploadAdvisory(BaseResponse, FileUpload):
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
        status, file_path, file_name = self._upload_file(save_path)

        if status != SUCCEED:
            return status

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


class VulUploadUnaffected(BaseResponse, FileUpload):
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
        status, file_path, file_name = self._upload_file(save_path)

        if status != SUCCEED:
            return status

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

    def _handle(self, proxy: HostProxy, args):
        """
        Handle the processing of exporting files

        Returns:
            str: status code
        """
        file_md5 = None
        host_info_list = query_user_hosts(
            host_list=args.get("host_list"), fields=["host_ip", "host_id", "host_name", "cluster_id"]
        )
        if not host_info_list:
            return NO_DATA, file_md5

        temp_file_path = None
        try:
            status, temp_file_path, _ = EmailNoticeManager(g.username, proxy, host_info_list).generate_temp_file()
            if status != SUCCEED:
                return status, file_md5

            # file_md5 = FileUtils.calculate_hash_code(temp_file_path)
            # if not file_md5:
            #     return SERVER_ERROR, file_md5

            # file_save_response = FileUtils.upload_file(file_md5, temp_file_path)
            # if file_save_response.status_code != http.HTTPStatus.OK:
            #     return SERVER_ERROR, file_md5

            # create_timestamp = int(time.time())
            # file_info = FileModel(
            #     file_name=f"host_cve_info{time.strftime('%Y%m%d%H%M%S', time.localtime(create_timestamp))}.csv",
            #     file_md5=file_md5,
            #     username=g.username,
            #     file_size=os.path.getsize(temp_file_path),
            #     create_timestamp=create_timestamp,
            #     expiration_timestamp=create_timestamp + 24 * 60 * 60,
            # )

            # with FileProxy() as file_proxy:
            #     status = file_proxy.insert_new_file_info(file_info, g.username)
            #     if status != SUCCEED:
            #         return SERVER_ERROR, file_md5

        except OSError as error:
            LOGGER.error(error)
            return SERVER_ERROR, file_md5
        # finally:
        #     # Delete the temporary file if it exists
        #     if temp_file_path and os.path.isfile(temp_file_path):
        #         os.remove(temp_file_path)

        return SUCCEED, temp_file_path

    @BaseResponse.handle(proxy=HostProxy, schema=ExportCveExcelSchema)
    def post(self, callback: HostProxy, **params):
        """
        Get rar/zip/rar compressed package or single xml file, decompress and insert data into database

        Returns:
            dict: response body
        """
        status_code, file_path = self._handle(callback, params)
        if status_code != SUCCEED:
            return self.response(code=status_code, message="Generating file failed due to internal server error!")
        return make_download_response(file_path, f"host_cve_info_{time.strftime('%Y%m%d%H%M%S', time.localtime())}.csv")


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
        host_ids = query_user_hosts(params.get("host_ids", []))
        status_code, unfix_cve_packages = callback.get_cve_unfixed_packages(cve_id=params["cve_id"], host_ids=host_ids)
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
        host_ids = query_user_hosts(params.get("host_ids", []))
        status_code, unfix_cve_packages = callback.get_cve_fixed_packages(cve_id=params["cve_id"], host_ids=host_ids)
        return self.response(code=status_code, data=unfix_cve_packages)


class VulGetCvePackageHost(BaseResponse):
    """
    Restful interface for get cve package host list
    """

    def _handle(self, params, callback: CveProxy):
        status, response_body = callback.get_cve_packages_host(params)
        host_list = response_body.get("result", [])
        if status != SUCCEED or len(host_list) == 0:
            return status, response_body

        host_list = response_body.get("result")
        query_fields = ["host_id", "host_ip", "host_name", "cluster_id"]
        host_infos = query_user_hosts(host_list, query_fields)
        response_body["result"] = sorted(host_infos, key=lambda x: host_list.index(x["host_id"]))
        return status, response_body

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
        status_code, hosts = self._handle(params, callback)
        return self.response(code=status_code, data=hosts)
