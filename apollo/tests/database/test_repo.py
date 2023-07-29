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
Description:
"""
import unittest

from sqlalchemy import func
from vulcanus.restful.resp.state import (
    PARTIAL_SUCCEED,
    SUCCEED,
    NO_DATA,
    DATA_DEPENDENCY_ERROR,
)

from apollo.database.proxy.repo import RepoProxy
from apollo.database.table import Repo
from apollo.tests.database.helper import setup_mysql_db, tear_down_mysql_db


class TestRepoDatabase(unittest.TestCase):
    repo_database = RepoProxy()
    repo_database.connect()

    @classmethod
    def setUpClass(cls):
        setup_mysql_db()

    @classmethod
    def tearDownClass(cls):
        tear_down_mysql_db()

    def test_import_repo(self):
        # add exist repo
        data = {"username": "admin", "repo_name": "repo1", "repo_data": ""}
        repo_count = (
            self.repo_database.session.query(func.count(Repo.repo_id))
            .filter(Repo.username == data["username"])
            .scalar()
        )
        self.assertEqual(self.repo_database.import_repo(data), 1105)

        new_repo_count = (
            self.repo_database.session.query(func.count(Repo.repo_id))
            .filter(Repo.username == data["username"])
            .scalar()
        )
        self.assertEqual(repo_count, new_repo_count)

        # add a new repo
        repo_count = (
            self.repo_database.session.query(func.count(Repo.repo_id))
            .filter(Repo.username == data["username"])
            .scalar()
        )

        data = {"username": "admin", "repo_name": "repo2", "repo_data": ""}
        self.assertEqual(self.repo_database.import_repo(data), 200)

        new_repo_count = (
            self.repo_database.session.query(func.count(Repo.repo_id))
            .filter(Repo.username == data["username"])
            .scalar()
        )
        self.assertEqual(repo_count + 1, new_repo_count)

    def test_query_repo(self):
        # query doesn't exist repo info
        data = {
            "username": "admin",
            "repo_name_list": ["repo_not_exist1", "repo_not_exist2"],
        }
        self.assertEqual(self.repo_database.get_repo(data), (NO_DATA, {"result": []}))

        # query partial exist repo info
        data = {"username": "admin", "repo_name_list": ["repo1", "repo_not_exist"]}
        expected_query_result = {
            "result": [
                {
                    "repo_id": 2,
                    "repo_name": "repo1",
                    "repo_attr": "openEuler 21.09",
                    "repo_data": "[update]",
                }
            ]
        }
        self.assertEqual(self.repo_database.get_repo(data), (PARTIAL_SUCCEED, expected_query_result))

        # query exist repo info.
        data = {"username": "admin", "repo_name_list": ["repo1"]}
        expected_query_result = {
            "result": [
                {
                    "repo_id": 2,
                    "repo_name": "repo1",
                    "repo_attr": "openEuler 21.09",
                    "repo_data": "[update]",
                }
            ]
        }
        self.assertEqual(self.repo_database.get_repo(data), (SUCCEED, expected_query_result))

        # query all repo. pay attention, a test repo is added in previous test case
        data = {"username": "admin", "repo_name_list": []}
        expected_query_result = {
            "result": [
                {
                    "repo_id": 2,
                    "repo_name": "repo1",
                    "repo_attr": "openEuler 21.09",
                    "repo_data": "[update]",
                },
                {"repo_id": 5, "repo_name": "repo2", "repo_attr": "", "repo_data": ""},
            ]
        }
        query_result = self.repo_database.get_repo(data)
        query_result[1]["result"].sort(key=lambda x: x["repo_id"])
        self.assertEqual(query_result, (SUCCEED, expected_query_result))

    def test_delete_repo(self):
        # delete in used repo
        data = {"username": "admin", "repo_name_list": ["repo1"]}
        self.assertEqual(self.repo_database.delete_repo(data), DATA_DEPENDENCY_ERROR)

        # delete partial in used repo. The repos in database are: repo1, repo2, repo3
        data = {"username": "admin", "repo_name_list": ["repo1", "repo3"]}
        delete_result = self.repo_database.delete_repo(data)
        self.assertEqual(delete_result, DATA_DEPENDENCY_ERROR)

        # delete exist repo. The repos in database are: repo1, repo2, repo3
        data = {"username": "admin", "repo_name_list": ["repo2", "repo3"]}
        delete_result = self.repo_database.delete_repo(data)
        self.assertEqual(delete_result, SUCCEED)

        # delete not exist repo. The repos in database are: repo1
        data = {"username": "admin", "repo_name_list": ["not_exist_repo"]}
        delete_result = self.repo_database.delete_repo(data)
        self.assertEqual(delete_result, SUCCEED)

    def test_update_repo(self):
        # update exist repo
        data = {"username": "admin", "repo_name": "repo1", "repo_data": "changed data"}
        self.assertEqual(self.repo_database.update_repo(data), SUCCEED)

        data = {"username": "admin", "repo_name_list": ["repo1"]}
        expected_query_result = {
            "result": [
                {
                    "repo_id": 2,
                    "repo_name": "repo1",
                    "repo_attr": "",
                    "repo_data": "changed data",
                }
            ]
        }
        self.assertEqual(self.repo_database.get_repo(data), (SUCCEED, expected_query_result))

        # update doesn't exist repo
        data = {"username": "admin", "repo_name": "repo10", "repo_data": "changed data"}
        self.assertEqual(self.repo_database.update_repo(data), NO_DATA)
