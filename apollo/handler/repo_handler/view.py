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
from flask import jsonify
from vulcanus.restful.resp import make_response
from vulcanus.restful.resp.state import SUCCEED
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration
from apollo.database.proxy.repo import RepoProxy
from apollo.function.schema.repo import ImportYumRepoSchema, UpdateYumRepoSchema, GetYumRepoSchema, DeleteYumRepoSchema
from apollo.handler.repo_handler.helper import get_template_stream_response


class VulImportYumRepo(BaseResponse):
    """
    Restful interface for importing yum repo
    """

    @BaseResponse.handle(schema=ImportYumRepoSchema, proxy=RepoProxy, config=configuration)
    def post(self, callback: RepoProxy, **params):
        """
        Import repo into database

        Args:
            repo_name (str): repo's name
            repo_data (str): repo's data

        Returns:
            dict: response body

        """
        status_code = callback.import_repo(params)
        return self.response(code=status_code)


class VulUpdateYumRepo(BaseResponse):
    """
    Restful interface for updating yum repo
    """

    @BaseResponse.handle(schema=UpdateYumRepoSchema, proxy=RepoProxy, config=configuration)
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

    @BaseResponse.handle(schema=GetYumRepoSchema, proxy=RepoProxy, config=configuration)
    def post(self, callback: RepoProxy, **params):
        """
        Get repo from database

        Args:
            repo_name_list (list): repos' name list

        Returns:
            dict: response body

        """
        status_code, result = callback.get_repo(params)
        return self.response(code=status_code, data=result)


class VulDeleteYumRepo(BaseResponse):
    """
    Restful interface for deleting yum repo
    """

    @BaseResponse.handle(schema=DeleteYumRepoSchema, proxy=RepoProxy, config=configuration)
    def delete(self, callback: RepoProxy, **params):
        """
        Delete repo from database

        Args:
            repo_name_list (list): repos' name list

        Returns:
            dict: response body

        """
        status_code = callback.delete_repo(params)
        return self.response(code=status_code)


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
