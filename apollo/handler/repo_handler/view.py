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

from vulcanus.restful.response import BaseResponse
from vulcanus.restful.status import SUCCEED, make_response
from apollo.function.schema.repo import ImportYumRepoSchema, UpdateYumRepoSchema, \
    GetYumRepoSchema, DeleteYumRepoSchema
from apollo.database.proxy.repo import RepoProxy
from apollo.database import SESSION
from apollo.handler.repo_handler.helper import get_template_stream_response


class VulImportYumRepo(BaseResponse):
    """
    Restful interface for importing yum repo
    """
    def post(self):
        """
        Import repo into database

        Args:
            repo_name (str): repo's name
            repo_data (str): repo's data

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(ImportYumRepoSchema, RepoProxy(),
                                              "import_repo", SESSION))


class VulUpdateYumRepo(BaseResponse):
    """
    Restful interface for updating yum repo
    """
    def post(self):
        """
        Update repo info in database

        Args:
            repo_name (str): repo's name
            repo_data (str): repo's data

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(UpdateYumRepoSchema, RepoProxy(),
                                              "update_repo", SESSION))


class VulGetYumRepo(BaseResponse):
    """
    Restful interface for getting yum repo
    """
    def post(self):
        """
        Get repo from database

        Args:
            repo_name_list (list): repos' name list

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(GetYumRepoSchema, RepoProxy(), "get_repo",
                                              SESSION))


class VulDeleteYumRepo(BaseResponse):
    """
    Restful interface for deleting yum repo
    """
    def delete(self):
        """
        Delete repo from database

        Args:
            repo_name_list (list): repos' name list

        Returns:
            dict: response body

        """
        return jsonify(self.handle_request_db(DeleteYumRepoSchema, RepoProxy(), "delete_repo",
                                              SESSION))


class VulGetRepoTemplate(BaseResponse):
    """
    Restful interface for getting a template repo
    """
    def get(self):
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
