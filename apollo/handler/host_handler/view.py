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
Description: Handle about host related operation
"""
from flask import jsonify

from vulcanus.restful.response import BaseResponse
from apollo.function.schema.host import GetHostStatusSchema, GetHostListSchema, \
    GetHostInfoSchema, GetHostCvesSchema
from apollo.database.proxy.host import HostProxy, HostMysqlProxy
from apollo.database import SESSION
from apollo.conf import configuration


class VulGetHostStatus(BaseResponse):
    """
    Restful interface for getting hosts status
    """
    def post(self):
        """
        Get hosts status

        Args:
            host_list (list): host id list

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetHostStatusSchema, HostMysqlProxy(),
                                              "get_hosts_status", SESSION))


class VulGetHostList(BaseResponse):
    """
    Restful interface for getting host list
    """
    def post(self):
        """
        Get host list

        Args:
            sort (str): can be chosen from last_scan, cve_num (optional)
            direction (str): asc or desc, default asc (optional)
            page (int): current page in front (optional)
            per_page (int): host number of each page (optional)
            filter (dict): filter condition (optional)

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetHostListSchema, HostMysqlProxy(),
                                              "get_host_list", SESSION))


class VulGetHostInfo(BaseResponse):
    """
    Restful interface for getting detailed info of a host
    """
    def get(self):
        """
        Get detailed info of a cve

        Args:
            cve_id (str): cve id

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetHostInfoSchema, HostMysqlProxy(),
                                              "get_host_info", SESSION))


class VulGetHostCves(BaseResponse):
    """
    Restful interface for getting CVEs info of a host
    """
    def post(self):
        """
        Get hosts info of a cve

        Args:
            host_id (str): host id
            sort (str): can be chose from publish_time, cvss_score
            direction (str): asc or desc, default asc (optional)
            page (int): current page in front (optional)
            per_page (int): cve number of each page (optional)
            filter (dict): filter condition

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetHostCvesSchema, HostProxy(configuration),
                                              "get_host_cve", SESSION))
