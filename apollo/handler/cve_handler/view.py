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
from time import sleep

from flask import jsonify

from apollo.conf import configuration
from apollo.conf.constant import FILE_UPLOAD_PATH
from apollo.database import SESSION
from apollo.database.proxy.cve import CveProxy, CveMysqlProxy
from apollo.function.customize_exception import ParseAdvisoryError
from apollo.function.schema.cve import GetCveListSchema, GetCveInfoSchema, GetCveHostsSchema, \
    GetCveTaskHostSchema, SetCveStatusSchema, GetCveActionSchema
from apollo.handler.cve_handler.manager.decompress import unzip
from apollo.handler.cve_handler.manager.parse_advisory import parse_security_advisory
from apollo.handler.cve_handler.manager.parse_unaffected import parse_unaffected_cve
from vulcanus.database.helper import judge_return_code
from vulcanus.log.log import LOGGER
from vulcanus.restful.response import BaseResponse
from vulcanus.restful.status import SUCCEED, DATABASE_CONNECT_ERROR, DATABASE_INSERT_ERROR, \
    SERVER_ERROR, WRONG_FILE_FORMAT


class VulGetCveOverview(BaseResponse):
    """
    Restful interface for getting CVE's overview info
    """

    def get(self):
        """
        Get overview of cve severity

        Args:

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(None, CveMysqlProxy(), "get_cve_overview", SESSION))


class VulGetCveList(BaseResponse):
    """
    Restful interface for getting cve list of all hosts
    """

    def post(self):
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
        return jsonify(self.handle_request_db(GetCveListSchema, CveProxy(configuration),
                                              "get_cve_list", SESSION))


class VulGetCveInfo(BaseResponse):
    """
    Restful interface for getting detailed info of a cve
    """

    def get(self):
        """
        Get detailed info of a cve

        Args:
            cve_id (str): cve id

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetCveInfoSchema, CveProxy(configuration),
                                              "get_cve_info", SESSION))


class VulGetCveHosts(BaseResponse):
    """
    Restful interface for getting hosts info of a cve
    """

    def post(self):
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
        return jsonify(self.handle_request_db(GetCveHostsSchema, CveMysqlProxy(), "get_cve_host",
                                              SESSION))


class VulGetCveTaskHost(BaseResponse):
    """
    Restful interface for getting each CVE's hosts' basic info (id, ip, name)
    """

    def post(self):
        """
        Get basic info of hosts which have specific cve

        Args:
            cve_list (list): cve id list

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetCveTaskHostSchema, CveMysqlProxy(),
                                              "get_cve_task_hosts", SESSION))


class VulSetCveStatus(BaseResponse):
    """
    Restful interface for setting status of cve
    """

    def post(self):
        """
        Set status of cve

        Args:
            cve_list (list): cve id list
            status (str): status of cve

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(SetCveStatusSchema, CveMysqlProxy(),
                                              "set_cve_status", SESSION))


class VulGetCveAction(BaseResponse):
    """
    Restful interface for getting action after cve fixed
    """

    def post(self):
        """
        Get action after fixing cve

        Args:
            cve_list (list): cve id list

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetCveActionSchema, CveMysqlProxy(),
                                              "get_cve_action", SESSION))


class VulUploadAdvisory(BaseResponse):
    """
    Restful interface for importing security advisory xml (compressed files or single file)
    """

    def _handle(self):
        """
        Handle uploading security advisory xml files
        Returns:
            int: status code
        """
        if not os.path.exists(FILE_UPLOAD_PATH):
            os.mkdir(FILE_UPLOAD_PATH)
        save_path = FILE_UPLOAD_PATH
        status, username, file_name = self.verify_upload_request(save_path)

        if status != SUCCEED:
            return status

        file_path = os.path.join(save_path, username, file_name)
        # connect to database
        proxy = CveProxy(configuration)
        if not proxy.connect(SESSION):
            LOGGER.error("Connect to database fail.")
            return DATABASE_CONNECT_ERROR

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
            cve_rows, cve_pkg_rows, cve_pkg_docs = parse_security_advisory(
                file_path)
            os.remove(file_path)
        except (KeyError, ParseAdvisoryError) as error:
            os.remove(file_path)
            LOGGER.error(
                "Some error occurred when parsing advisory '%s'." % file_name)
            LOGGER.error(error)
            return SERVER_ERROR

        status_code = proxy.save_security_advisory(
            file_name, cve_rows, cve_pkg_rows, cve_pkg_docs)

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
            try:
                cve_rows, cve_pkg_rows, cve_pkg_docs = parse_security_advisory(
                    file_path)
            except (KeyError, ParseAdvisoryError) as error:
                fail_list.append(file_name)
                LOGGER.error(
                    "Some error occurred when parsing advisory '%s'." % file_name)
                LOGGER.error(error)
                continue
            except IsADirectoryError as error:
                fail_list.append(file_name)
                LOGGER.error(
                    "Folder %s cannot be parsed as an advisory." % file_name)
                LOGGER.error(error)
                continue
            # elasticsearch need 1 second to update doc
            status_code = proxy.save_security_advisory(file_name, cve_rows, cve_pkg_rows,
                                                       cve_pkg_docs)
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

    def post(self):
        """
        Get rar/zip/rar compressed package or single xml file, decompress and insert data
        into database

        Returns:
            dict: response body
        """
        return jsonify(self.make_response(self._handle()))


class VulUploadUnaffected(BaseResponse):
    """
    Restful interface for importing unaffected cve xml (compressed files or single file)
    """

    def _handle(self):
        """
        Handle uploading unaffected cve xml files
        Returns:
            int: status code
        """
        save_path = os.path.join(FILE_UPLOAD_PATH)
        status, username, file_name = self.verify_upload_request(save_path)

        if status != SUCCEED:
            return status

        file_path = os.path.join(save_path, username, file_name)
        # connect to database
        proxy = CveProxy(configuration)
        if not proxy.connect(SESSION):
            LOGGER.error("Connect to database fail.")
            return DATABASE_CONNECT_ERROR

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
            os.remove(file_path)
        except (KeyError, ParseAdvisoryError) as error:
            os.remove(file_path)
            LOGGER.error("Some error occurred when parsing unaffected cve advisory '%s'." % file_name)
            LOGGER.error(error)
            return SERVER_ERROR

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
            try:
                cve_rows, cve_pkg_rows, doc_list = parse_unaffected_cve(file_path)
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

    def post(self):
        """
        Get rar/zip/rar compressed package or single xml file, decompress and insert data
        into database

        Returns:
            dict: response body
        """
        return jsonify(self.make_response(self._handle()))


class VulExportExcel(BaseResponse):
    """
    Restful interface for export cve to excel
    """

    def post(self):
        """
        Get rar/zip/rar compressed package or single xml file, decompress and insert data
        into database

        Returns:
            dict: response body
        """
        return self.handle_send_file(None, CveProxy(configuration),
                                     "save_to_csv", SESSION)
