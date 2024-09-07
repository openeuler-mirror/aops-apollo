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
Description: Handle about repo related operation
"""
from urllib.parse import urlencode

from flask import jsonify, g
from vulcanus.conf.constant import HOSTS_FILTER, UserRoleType
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp import make_response
from vulcanus.restful.resp.state import SUCCEED, DATA_DEPENDENCY_ERROR, DATABASE_QUERY_ERROR, PERMESSION_ERROR
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration, cache
from apollo.database.proxy.repo import RepoProxy
from apollo.function.schema.repo import ImportYumRepoSchema, UpdateYumRepoSchema, GetYumRepoSchema, DeleteYumRepoSchema
from apollo.handler.repo_handler.helper import get_template_stream_response


class VulImportYumRepo(BaseResponse):
    """
    Restful interface for importing yum repo
    """

    @BaseResponse.handle(schema=ImportYumRepoSchema, proxy=RepoProxy)
    def post(self, callback: RepoProxy, **params):
        """
        Import repo into database

        Args:
            repo_name (str): repo's name
            repo_data (str): repo's data

        Returns:
            dict: response body

        """
        if cache.user_role != UserRoleType.ADMINISTRATOR:
            return self.response(code=PERMESSION_ERROR, message="No permission to add new repo!")

        current_cluster_info = cache.location_cluster
        if not current_cluster_info:
            LOGGER.debug("Failed to get current cluster id")
            return self.response(code=DATABASE_QUERY_ERROR)

        params["cluster_id"] = current_cluster_info.get("cluster_id")
        status_code = callback.import_repo(params)
        return self.response(code=status_code)


class VulUpdateYumRepo(BaseResponse):
    """
    Restful interface for updating yum repo
    """

    @BaseResponse.handle(schema=UpdateYumRepoSchema, proxy=RepoProxy)
    def post(self, callback: RepoProxy, **params):
        """
        Update repo info in database

        Args:
            repo_name (str): repo's name
            repo_data (str): repo's data

        Returns:
            dict: response body

        """
        status_code = callback.update_repo(params)
        return self.response(code=status_code)


class VulGetYumRepo(BaseResponse):
    """
    Restful interface for getting yum repo
    """

    def _handle(self, params: dict, proxy: RepoProxy):
        """
        Query repo info handle
        """
        cluster_info_dic = cache.get_user_clusters()
        if not cluster_info_dic:
            return SUCCEED, []

        status_code, result = proxy.get_repo(params.get("repo_id_list", []), list(cluster_info_dic.keys()))
        if status_code != SUCCEED:
            return status_code, []

        for repo in result:
            repo["cluster_name"] = cluster_info_dic.get(repo.get("cluster_id"))
        return status_code, result

    @BaseResponse.handle(schema=GetYumRepoSchema, proxy=RepoProxy)
    def post(self, callback: RepoProxy, **params):
        """
        Get repo from database

        Args:
            repo_name_list (list): repos' name list

        Returns:
            dict: response body

        """
        status_code, result = self._handle(params, callback)
        return self.response(code=status_code, data=result)


class VulDeleteYumRepo(BaseResponse):
    """
    Restful interface for deleting yum repo
    """

    def _query_repo_in_use(self):
        """
        Query which repositories have been applied
        """
        request_args = {"fields": ["repo_id"]}
        url = f"http://{configuration.domain}{HOSTS_FILTER}?{urlencode(request_args)}"
        response_data = self.get_response(method="Get", url=url, header=g.headers)
        status = response_data.get("label")
        if status != SUCCEED:
            LOGGER.error("Failed to query repo in use.")
            return status, set()

        repo_in_use = set()
        for repo in response_data.get("data", []):
            repo_id = repo.get("repo_id")
            if repo_id is not None:
                repo_in_use.add(repo_id)

        return response_data.get("label"), repo_in_use

    def _handle(self, repo_id_list, proxy: RepoProxy):
        """
        Delete repo handle
        """
        user_role = cache.user_role
        if not user_role:
            return self.response(code=PERMESSION_ERROR, message="Failed to query user permission information!")

        if user_role != UserRoleType.ADMINISTRATOR:
            return self.response(code=PERMESSION_ERROR, message="No permission to delete repo!")
        # query repo in use
        status, repo_in_use = self._query_repo_in_use()
        if status != SUCCEED:
            LOGGER.error("Failed to query repo in use.")
            return self.response(code=status, message="Failed to query repo in use.")

        dependency_data = repo_in_use.intersection(set(repo_id_list))
        if dependency_data:
            LOGGER.debug(f"Repos are still in use when deleting repo: {dependency_data}.")
            return self.response(code=DATA_DEPENDENCY_ERROR, message="Some repos are still in use.")

        user_cluster_info = cache.get_user_clusters()
        if not user_cluster_info:
            LOGGER.error("Failed to get user cluster info.")
            return self.response(code=DATABASE_QUERY_ERROR, message="Failed to get user cluster info.")

        return self.response(code=proxy.delete_repo(repo_id_list, user_cluster_info.keys()))

    @BaseResponse.handle(schema=DeleteYumRepoSchema, proxy=RepoProxy)
    def delete(self, callback: RepoProxy, **params):
        """
        Delete repo from database

        Args:
            repo_name_list (list): repos' name list

        Returns:
            dict: response body

        """
        return self._handle(params.get("repo_id_list"), callback)


class VulGetRepoTemplate(BaseResponse):
    """
    Restful interface for getting a template repo
    """

    @BaseResponse.handle()
    def get(self, **params):
        """
        Getting a template repo

        Args:

        Returns:
            dict: response body

        """
        args, verify_code = self.verify_request()
        if verify_code != SUCCEED:
            return jsonify(make_response(verify_code))

        response = get_template_stream_response()
        return response
