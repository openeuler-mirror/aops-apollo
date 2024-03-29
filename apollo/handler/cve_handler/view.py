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
import glob
import os
import shutil

from vulcanus.database.helper import judge_return_code
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED, DATABASE_INSERT_ERROR, WRONG_FILE_FORMAT, NO_DATA, SERVER_ERROR
from vulcanus.restful.response import BaseResponse

from apollo.conf.constant import FILE_UPLOAD_PATH, CSV_SAVED_PATH, FILE_NUMBER
from apollo.database.proxy.cve import CveProxy, CveMysqlProxy
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
from apollo.function.utils import make_download_response
from apollo.handler.cve_handler.manager.compress_manager import unzip, compress_cve
from apollo.handler.cve_handler.manager.parse_advisory import parse_security_advisory
from apollo.handler.cve_handler.manager.parse_unaffected import parse_unaffected_cve
from apollo.handler.cve_handler.manager.save_to_csv import export_csv


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
        status_code, result = callback.get_cve_overview(params)
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
        status_code, result = callback.get_cve_host(params)
        return self.response(code=status_code, data=result)


class VulGetCveTaskHost(BaseResponse):
    """
    Restful interface for getting each CVE's hosts' basic info (id, ip, name)
    """

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
        status_code, result = callback.get_cve_task_hosts(params)
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
                if not all([security_cvrf_info.cve_rows, security_cvrf_info.cve_pkg_rows,
                            security_cvrf_info.cve_pkg_docs]):
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
            return make_download_response(os.path.join(fileinfo.get("filepath"), fileinfo.get("filename")),
                                          fileinfo.get("filename"))
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
