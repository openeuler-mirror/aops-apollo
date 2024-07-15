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
from typing import Dict, List, Set, Tuple

from flask import g
from vulcanus.conf.constant import HOSTS
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp import state
from vulcanus.restful.response import BaseResponse

from apollo.conf import cache, configuration
from apollo.conf.constant import HostStatus
from apollo.database.proxy.cve import CveMysqlProxy
from apollo.database.proxy.host import HostProxy
from apollo.database.proxy.repo import RepoProxy
from apollo.function.schema.host import GetHostCvesSchema, GetHostInfoSchema, GetHostListSchema, GetHostStatusSchema
from apollo.function.utils import query_user_hosts, paginate_data


class VulGetHostStatus(BaseResponse):
    """
    Restful interface for getting hosts status
    """

    def _query_scanning_host_list(self) -> Tuple[str, Set[str]]:
        """
        Query scanning host list from Redis.

        Returns:
            tuple: A tuple containing status and scanning host set.
        """
        try:
            # example {"host_id1":"scanning timestamp info", "host_id2":"scanning timestamp info}
            scanning_host_dic: Dict[str, str] = cache.hash(cache.SCANNING_HOST_KEY) or {}
            return state.SUCCEED, scanning_host_dic.keys()
        except Exception as error:
            LOGGER.error(error)
            return state.DATABASE_QUERY_ERROR, []

    def _handle(self, host_list: List[str]):
        """
        handle for query host status
        """
        if len(host_list) == 0:
            return state.SUCCEED, {}

        # check host list is_valid
        if len(query_user_hosts(host_list=host_list)) != len(host_list):
            LOGGER.error("Host validity check failed due to an error accessing the host service.")
            return state.PARAM_ERROR, {}

        # query scanning host list from redis
        status, scanning_host_list = self._query_scanning_host_list()
        if status != state.SUCCEED:
            return status, {}

        result_dict = {}
        for host_id in host_list:
            if host_id in scanning_host_list:
                result_dict[host_id] = HostStatus.SCANNING
            else:
                result_dict[host_id] = HostStatus.ONLINE
        return state.SUCCEED, result_dict

    @BaseResponse.handle(schema=GetHostStatusSchema)
    def post(self, **params):
        """
        Get hosts status

        Args:
            host_list (list): host id list

        Returns:
            dict: response body

        """
        status_code, result = self._handle(params.get("host_list"))
        return self.response(code=status_code, data={"result": result})


class VulGetHostList(BaseResponse):
    """
    Restful interface for getting host list
    """

    @staticmethod
    def _update_host_cve_info(host_info_data, host_cve_info_rows, cluster_info, repo_info):
        """
        update cve info to host info dict
        """
        host_cve_count_info = {row.host_id: row for row in host_cve_info_rows}
        for host_info in host_info_data:
            host_cve_count = host_cve_count_info.get(host_info.get("host_id"))
            host_info.update(
                {
                    "unfixed_cve_num": host_cve_count.unfixed_cve_num if host_cve_count else 0,
                    "fixed_cve_num": host_cve_count.fixed_cve_num if host_cve_count else 0,
                    "cluster_name": cluster_info.get(host_info.get("cluster_id")),
                    "repo_name": repo_info.get(host_info.get("repo_id")),
                }
            )
        return host_info_data

    def _handle(self, data):
        """
        handle func
        """
        fields = [
            "host_id",
            "host_ip",
            "host_name",
            "host_group_id",
            "host_group_name",
            "repo_id",
            "last_scan",
            "cluster_id",
        ]
        host_info_list = query_user_hosts(fields=fields, **data.get("filter", {}))
        if not host_info_list:
            return state.SUCCEED, {"total_count": 0, "total_page": 0, "result": []}
        # query host cve count info
        status, host_cve_info_list = self.proxy.get_host_cve_fixed_info(
            [host.get("host_id") for host in host_info_list]
        )
        if status != state.SUCCEED:
            return status, {}

        # query cluster info with repo info
        cluster_info = cache.get_user_clusters()
        repo_id_list = [host.get("repo_id") for host in host_info_list if host.get("repo_id")]
        with RepoProxy() as repo_proxy:
            status, repo_info = repo_proxy.get_repo(repo_id_list, None)

        repo_info = {repo.get("repo_id"): repo.get("repo_name") for repo in repo_info}
        # update host info
        host_info_list = self._update_host_cve_info(host_info_list, host_cve_info_list, cluster_info, repo_info)

        if data.get("sort"):
            sort_key = data.get("sort")
            sort_direction = data.get("direction")
            host_info_list = sorted(
                host_info_list,
                key=lambda x: x[sort_key],
                reverse=sort_direction == "desc",
            )
        per_page = data.get("per_page")
        page = data.get("page")
        if per_page and page:
            total_count, total_page, paginated_data = paginate_data(host_info_list, per_page, page)
        else:
            total_page = 1
            total_count = len(host_info_list)
            paginated_data = host_info_list

        return state.SUCCEED, {"result": paginated_data, "total_page": total_page, "total_count": total_count}

    @BaseResponse.handle(schema=GetHostListSchema, proxy=CveMysqlProxy)
    def post(self, callback: CveMysqlProxy, **params):
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
        self.proxy = callback
        status_code, result = self._handle(params)
        return self.response(code=status_code, data=result)


class VulGetHostInfo(BaseResponse):
    """
    Restful interface for getting detailed info of a host
    """

    def _query_host_info(self, host_id):
        """
        Query which repositories have been applied
        """
        url = f"http://{configuration.domain}{HOSTS}/{host_id}"
        response_data = self.get_response(method="Get", url=url, header=g.headers)
        return response_data.get("label"), response_data.get("data", [])

    @staticmethod
    def _turn_data_to_dict(host_info, host_cve_info_row):
        """
        Generate response body data

        Args:
            host_info
            host_cve_info_row

        Returns:
            dict: e.g
                {
                    "result": {
                        "host_name": "name1",
                        "host_ip": "1.1.1.1",
                        "host_group": "group1",
                        "repo": "20.03-update",
                        "affected_cve_num": 12,
                        "unaffected_cve_num": 1,
                        "last_scan": 1111111111,
                        "reboot": true/false
                    }
                }
        """
        return {
            "host_name": host_info.get("host_name"),
            "host_ip": host_info.get("host_ip"),
            "host_group": host_info.get("host_group_name"),
            "repo_id": host_info.get("repo_id"),
            "last_scan": host_info.get("last_scan"),
            "reboot": host_info.get("reboot"),
            "affected_cve_num": host_cve_info_row.affected_cve_num if host_cve_info_row else 0,
            "unaffected_cve_num": host_cve_info_row.unaffected_cve_num if host_cve_info_row else 0,
            "fixed_cve_num": host_cve_info_row.fixed_cve_num if host_cve_info_row else 0,
            "cluster_id": host_info.get("cluster_id"),
            "cluster_name": host_info.get("cluster_name"),
            "repo_name": host_info.get("repo_name"),
        }

    def _handle(self, host_id, proxy: CveMysqlProxy):
        status, host_info = self._query_host_info(host_id)
        if status != state.SUCCEED:
            LOGGER.error("Failed to query host info.")
            return status, {}

        with RepoProxy() as repo_proxy:
            status, repo_info = repo_proxy.get_repo([host_info.get("repo_id")], None)
            host_info["repo_name"] = repo_info[0].get("repo_name") if repo_info else None
        status, query_row = proxy.query_cve_num([host_id])
        if status != state.SUCCEED:
            LOGGER.error("Failed to query host cve info.")
            return status, {}

        return status, self._turn_data_to_dict(host_info, query_row)

    @BaseResponse.handle(schema=GetHostInfoSchema, proxy=CveMysqlProxy)
    def get(self, callback: CveMysqlProxy, **params):
        """
        Get detailed info of a cve

        Args:
            cve_id (str): cve id

        Returns:
            dict: response body

        """
        status_code, result = self._handle(params.get("host_id"), callback)
        return self.response(code=status_code, data=result)


class VulGetHostCves(BaseResponse):
    """
    Restful interface for getting CVEs info of a host
    """

    @BaseResponse.handle(schema=GetHostCvesSchema, proxy=HostProxy)
    def post(self, callback: HostProxy, **params):
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
        host_id = query_user_hosts([params.get("host_id")])
        if not host_id:
            LOGGER.debug("No host information found!")
            return self.response(code=state.PARAM_ERROR)
        status_code, result = callback.get_host_cve(params)
        return self.response(code=status_code, data=result)
