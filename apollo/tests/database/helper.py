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
import json
from time import sleep
from vulcanus.conf import configuration
from apollo.conf import configuration as settings


from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.scoping import scoped_session
from vulcanus.database.helper import drop_tables, create_database_engine
from vulcanus.database.proxy import MysqlProxy, ElasticsearchProxy

from apollo.tests import BaseTestCase
from apollo.conf.constant import CVE_INDEX, TASK_INDEX
from apollo.database.mapping import MAPPINGS
from apollo.database.table import (
    CveHostAssociation,
    TaskHostRepoAssociation,
    Cve,
    CveTaskAssociation,
    TaskCveHostAssociation,
    Task,
    Repo,
    CveAffectedPkgs,
    Base,
    User,
    Host,
    HostGroup,
    # create_vul_tables,
)
from apollo.database.table import create_vul_tables

__all__ = [
    "setup_mysql_db",
    "tear_down_mysql_db",
    "setup_es_db",
    "tear_down_es_db",
    "SESSION",
    "ENGINE",
]


class TestMysqlDb(MysqlProxy, BaseTestCase):
    def setUp(self) -> None:
        super().setUp()

    def add_user(self):
        user_data = {"username": "admin", "password": "123456", "email": "1231@163.com"}
        user = User(**user_data)
        self.session.add(user)
        self.session.commit()

    def add_hostgroup(self):
        host_group_data = {
            "host_group_id": 1,
            "host_group_name": "group1",
            "description": "des",
            "username": "admin",
        }
        host_group = HostGroup(**host_group_data)
        self.session.add(host_group)
        self.session.commit()

    def add_host(self):
        host_data_1 = {
            "host_name": "host1",
            "host_group_name": "group1",
            "host_group_id": 1,
            "user": "admin",
            "host_id": 1,
            "host_ip": "127.0.0.1",
            "management": False,
            "status": "done",
            "repo_name": "repo1",
            "last_scan": 123836100,
        }
        host = Host(**host_data_1)
        self.session.add(host)

        host_data_2 = {
            "host_name": "host2",
            "host_group_name": "group1",
            "host_group_id": 1,
            "user": "admin",
            "host_id": 2,
            "host_ip": "127.0.0.2",
            "management": False,
            "status": "scanning",
            "repo_name": "repo1",
            "last_scan": 123836152,
        }
        host = Host(**host_data_2)
        self.session.add(host)
        host_data_3 = {
            "host_name": "host3",
            "host_group_name": "group1",
            "host_group_id": 1,
            "user": "admin",
            "host_id": 3,
            "host_ip": "127.0.0.2",
            "management": False,
            "status": "scanning",
            "repo_name": "repo1",
            "last_scan": 123837152,
        }
        host = Host(**host_data_3)
        self.session.add(host)
        self.session.commit()

    def add_cve(self):
        cve_data_1 = {
            "cve_id": "qwfqwff3",
            "publish_time": "qwff",
            "severity": "High",
            "cvss_score": "7.2",
            "reboot": False,
        }
        cve_1 = Cve(**cve_data_1)
        self.session.add(cve_1)

        cve_data_2 = {
            "cve_id": "qwfqwff4",
            "publish_time": "asyubdqsd",
            "severity": "Medium",
            "cvss_score": "3",
            "reboot": True,
        }
        cve_2 = Cve(**cve_data_2)
        self.session.add(cve_2)

        cve_data_3 = {
            "cve_id": "qwfqwff5",
            "publish_time": "111",
            "severity": "Low",
            "cvss_score": "3",
            "reboot": False,
        }
        cve_3 = Cve(**cve_data_3)
        self.session.add(cve_3)

        cve_data_4 = {
            "cve_id": "qwfqwff6",
            "publish_time": "222",
            "severity": "Unknown",
            "cvss_score": "3",
            "reboot": False,
        }
        cve_4 = Cve(**cve_data_4)
        self.session.add(cve_4)
        self.session.commit()

    def add_repo(self):
        repo_data = {
            "repo_id": 2,
            "repo_name": "repo1",
            "repo_attr": "openEuler 21.09",
            "repo_data": "[update]",
            "username": "admin",
        }
        repo = Repo(**repo_data)
        self.session.add(repo)

        repo_data = {
            "repo_id": 3,
            "repo_name": "repo2",
            "repo_attr": "openEuler 21.09",
            "repo_data": "[update]",
            "username": "admin",
        }
        repo = Repo(**repo_data)
        self.session.add(repo)

        repo_data = {
            "repo_id": 4,
            "repo_name": "repo3",
            "repo_attr": "openEuler 21.09",
            "repo_data": "[update]",
            "username": "admin",
        }
        repo = Repo(**repo_data)
        self.session.add(repo)
        self.session.commit()

    def add_task(self):
        task_data = {
            "task_id": "1111111111poiuytrewqasdfghjklmnb",
            "task_type": "cve fix",
            "description": "cve task 1",
            "task_name": "fix cve",
            "latest_execute_time": 128467234,
            "need_reboot": 1,
            "auto_reboot": True,
            "username": "admin",
            "create_time": 123836139,
            "host_num": 2,
        }
        task = Task(**task_data)
        self.session.add(task)

        task_data = {
            "task_id": "2222222222poiuytrewqasdfghjklmnb",
            "task_type": "cve fix",
            "description": "cve task 2",
            "task_name": "fix cve",
            "latest_execute_time": 128467235,
            "need_reboot": 0,
            "auto_reboot": False,
            "username": "admin",
            "create_time": 123836140,
            "host_num": 1,
        }
        task = Task(**task_data)
        self.session.add(task)

        task_data = {
            "task_id": "aaaaaaaaaapoiuytrewqasdfghjklmnb",
            "task_type": "repo set",
            "description": "abcd",
            "task_name": "set repo",
            "latest_execute_time": 128467236,
            "need_reboot": 0,
            "auto_reboot": False,
            "username": "admin",
            "create_time": 123836141,
            "host_num": 1,
        }
        task = Task(**task_data)
        self.session.add(task)
        self.session.commit()

    def add_cve_task_info(self):
        task_cve_data = {
            "cve_id": "qwfqwff3",
            "task_id": "1111111111poiuytrewqasdfghjklmnb",
            "reboot": False,
            "progress": 1,
            "host_num": 2,
        }
        cve_task = CveTaskAssociation(**task_cve_data)
        self.session.add(cve_task)

        task_cve_data = {
            "cve_id": "qwfqwff4",
            "task_id": "1111111111poiuytrewqasdfghjklmnb",
            "reboot": True,
            "progress": 1,
            "host_num": 1,
        }
        cve_task = CveTaskAssociation(**task_cve_data)
        self.session.add(cve_task)

        task_cve_data = {
            "cve_id": "qwfqwff5",
            "task_id": "2222222222poiuytrewqasdfghjklmnb",
            "reboot": False,
            "progress": 0,
            "host_num": 1,
        }
        cve_task = CveTaskAssociation(**task_cve_data)
        self.session.add(cve_task)
        self.session.commit()

    def add_cve_host_match(self):
        cve_host_data = {
            "cve_id": "qwfqwff3",
            "host_id": 3,
            "affected": 0,
            "fixed": 1,
            "hotpatch": 1,
        }
        cve_host = CveHostAssociation(**cve_host_data)
        self.session.add(cve_host)

        cve_host_data = {
            "cve_id": "qwfqwff4",
            "host_id": 2,
            "affected": 1,
            "fixed": 1,
            "hotpatch": 0,
        }
        cve_host = CveHostAssociation(**cve_host_data)
        self.session.add(cve_host)

        cve_host_data = {
            "cve_id": "qwfqwff5",
            "host_id": 2,
            "affected": 1,
            "fixed": 0,
            "hotpatch": 1,
        }
        cve_host = CveHostAssociation(**cve_host_data)
        self.session.add(cve_host)

        cve_host_data = {
            "cve_id": "qwfqwff3",
            "host_id": 1,
            "affected": 0,
            "fixed": 1,
            "hotpatch": 0,
        }
        cve_host = CveHostAssociation(**cve_host_data)
        self.session.add(cve_host)

        cve_host_data = {
            "cve_id": "qwfqwff4",
            "host_id": 1,
            "affected": 1,
            "fixed": 1,
            "hotpatch": 1,
        }
        cve_host = CveHostAssociation(**cve_host_data)
        self.session.add(cve_host)
        self.session.commit()

    def add_task_cve_host(self):
        # task 1
        task_cve_host_data = {
            "cve_id": "qwfqwff3",
            "task_id": "1111111111poiuytrewqasdfghjklmnb",
            "host_id": 2,
            "host_name": "host2",
            "host_ip": "127.0.0.2",
            "status": "unknown",
        }
        task_cve_host = TaskCveHostAssociation(**task_cve_host_data)
        self.session.add(task_cve_host)

        task_cve_host_data = {
            "cve_id": "qwfqwff3",
            "task_id": "1111111111poiuytrewqasdfghjklmnb",
            "host_id": 1,
            "host_name": "host1",
            "host_ip": "127.0.0.1",
            "status": "running",
        }
        task_cve_host = TaskCveHostAssociation(**task_cve_host_data)
        self.session.add(task_cve_host)

        task_cve_host_data = {
            "cve_id": "qwfqwff4",
            "task_id": "1111111111poiuytrewqasdfghjklmnb",
            "host_id": 3,
            "host_name": "host1",
            "host_ip": "127.0.0.1",
            "status": "succeed",
        }
        task_cve_host = TaskCveHostAssociation(**task_cve_host_data)
        self.session.add(task_cve_host)

        # task 2
        task_cve_host_data = {
            "cve_id": "qwfqwff5",
            "task_id": "2222222222poiuytrewqasdfghjklmnb",
            "host_id": 2,
            "host_name": "host2",
            "host_ip": "127.0.0.2",
            "status": "fail",
        }
        task_cve_host = TaskCveHostAssociation(**task_cve_host_data)
        self.session.add(task_cve_host)
        self.session.commit()

    def add_task_repo_host(self):
        task_repo_host_data = {
            "repo_name": "repo1",
            "task_id": "aaaaaaaaaapoiuytrewqasdfghjklmnb",
            "host_id": 1,
            "host_name": "host1",
            "host_ip": "127.0.0.1",
            "status": "running",
        }
        task_repo_host = TaskHostRepoAssociation(**task_repo_host_data)
        self.session.add(task_repo_host)

        task_repo_host_data = {
            "repo_name": "repo2",
            "task_id": "aaaaaaaaaapoiuytrewqasdfghjklmnb",
            "host_id": 2,
            "host_name": "host2",
            "host_ip": "127.0.0.2",
            "status": "fail",
        }
        task_repo_host = TaskHostRepoAssociation(**task_repo_host_data)
        self.session.add(task_repo_host)
        self.session.commit()

    def add_cve_pkgs(self):
        cve_pkg_data = {
            "cve_id": "qwfqwff3",
            "package": "ansible",
            "package_version": "1.2.3",
            "os_version": "",
            "affected": 0,
        }
        cve_pkg = CveAffectedPkgs(**cve_pkg_data)
        self.session.add(cve_pkg)

        cve_pkg_data = {
            "cve_id": "qwfqwff3",
            "package": "tensorflow",
            "package_version": "1.2.3",
            "os_version": "openEuler-20.03-LTS-SP3",
            "affected": 0,
        }
        cve_pkg = CveAffectedPkgs(**cve_pkg_data)
        self.session.add(cve_pkg)

        cve_pkg_data = {
            "cve_id": "qwfqwff4",
            "package": "ansible",
            "package_version": "0.2.3",
            "os_version": "openEuler-20.03-LTS-SP3",
            "affected": 1,
        }
        cve_pkg = CveAffectedPkgs(**cve_pkg_data)
        self.session.add(cve_pkg)

        cve_pkg_data = {
            "cve_id": "qwfqwff4",
            "package": "redis",
            "package_version": "1.3",
            "os_version": "openEuler-20.03-LTS-SP3",
            "affected": 1,
        }
        cve_pkg = CveAffectedPkgs(**cve_pkg_data)
        self.session.add(cve_pkg)

        cve_pkg_data = {
            "cve_id": "qwfqwff5",
            "package": "",
            "package_version": "1.6.3",
            "os_version": "openEuler-20.03-LTS-SP3",
            "affected": 1,
        }
        cve_pkg = CveAffectedPkgs(**cve_pkg_data)
        self.session.add(cve_pkg)

        cve_pkg_data = {
            "cve_id": "qwfqwff6",
            "package": "redis",
            "package_version": "0.6.3",
            "os_version": "openEuler-20.03-LTS-SP3",
            "affected": 1,
        }
        cve_pkg = CveAffectedPkgs(**cve_pkg_data)
        self.session.add(cve_pkg)
        self.session.commit()


class TestEsDb(ElasticsearchProxy, BaseTestCase):
    def setUp(self) -> None:
        super().setUp()

    def add_task_result(self):
        # insert cve task result
        cve_task_result = {
            "task_id": "1111111111poiuytrewqasdfghjklmnb",
            "task_type": "cve",
            "latest_execute_time": 128467234,
            "task_result": [
                {
                    "host_id": 1,
                    "host_name": "host1",
                    "host_ip": "127.0.0.1",
                    "status": "running",
                    "check_items": [{"item": "check network", "result": True}],
                    "cves": [
                        {"cve_id": "qwfqwff3", "log": "", "result": "running"},
                        {"cve_id": "qwfqwff4", "log": "", "result": "fixed"},
                    ],
                },
                {
                    "host_id": 2,
                    "host_name": "host2",
                    "host_ip": "127.0.0.2",
                    "status": "fail",
                    "check_items": [{"item": "check network", "result": True}],
                    "cves": [{"cve_id": "qwfqwff3", "log": "", "result": "unfixed"}],
                },
            ],
        }
        data = {
            "task_id": "1111111111poiuytrewqasdfghjklmnb",
            "log": json.dumps(cve_task_result),
            "username": "admin",
        }
        self.insert(TASK_INDEX, data, document_id=data["task_id"])

        # insert repo task result
        repo_task_result = {
            "task_id": "aaaaaaaaaapoiuytrewqasdfghjklmnb",
            "task_type": "repo",
            "latest_execute_time": 123836141,
            "task_result": [
                {
                    "host_id": 1,
                    "host_name": "host1",
                    "host_ip": "127.0.0.1",
                    "status": "succeed",
                    "check_items": [{"item": "check network", "result": True}],
                    "log": "",
                }
            ],
        }
        data = {
            "task_id": "aaaaaaaaaapoiuytrewqasdfghjklmnb",
            "log": json.dumps(repo_task_result),
            "username": "admin",
        }
        self.insert(TASK_INDEX, data, document_id=data["task_id"])

    def add_cve_pkg_info(self):
        cve_doc = {
            "cve_id": "qwfqwff3",
            "description": "asdqwfqwf",
            "os_list": [
                {
                    "arch_list": [
                        {
                            "arch": "noarch",
                            "package": [
                                "ansible.oe1.noarch.rpm",
                                "tensorflow.oe1.noarch.rpm",
                            ],
                        },
                        {
                            "arch": "src",
                            "package": [
                                "ansible.oe1.src.rpm",
                                "tensorflow.oe1.src.rpm",
                            ],
                        },
                    ],
                    "os_version": "openEuler:20.03-LTS-SP1",
                    "update_time": "2021-12-31",
                }
            ],
        }
        self.insert(CVE_INDEX, cve_doc, document_id=cve_doc["cve_id"])

        cve_doc = {
            "cve_id": "qwfqwff4",
            "description": "sef",
            "os_list": [
                {
                    "arch_list": [
                        {
                            "arch": "noarch",
                            "package": [
                                "ansible.oe1.noarch.rpm",
                                "redis.oe1.noarch.rpm",
                            ],
                        },
                        {
                            "arch": "src",
                            "package": ["ansible.oe1.src.rpm", "redis.oe1.src.rpm"],
                        },
                    ],
                    "os_version": "openEuler:20.03-LTS-SP1",
                    "update_time": "2021-12-31",
                }
            ],
        }
        self.insert(CVE_INDEX, cve_doc, document_id=cve_doc["cve_id"])

        cve_doc = {"cve_id": "qwfqwff5", "description": "abc", "os_list": []}
        self.insert(CVE_INDEX, cve_doc, document_id=cve_doc["cve_id"])

        cve_doc = {
            "cve_id": "qwfqwff6",
            "description": "abcd",
            "os_list": [
                {
                    "arch_list": [
                        {"arch": "noarch", "package": ["redis.oe1.noarch.rpm"]},
                        {"arch": "src", "package": ["redis.oe1.src.rpm"]},
                    ],
                    "os_version": "openEuler:20.03-LTS-SP1",
                    "update_time": "2021-12-31",
                }
            ],
        }
        self.insert(CVE_INDEX, cve_doc, document_id=cve_doc["cve_id"])


for config in [config for config in dir(settings) if not config.startswith("_")]:
    setattr(configuration, config, getattr(settings, config))

test_es_db = TestEsDb()
test_mysql_db = TestMysqlDb()

# create engine to database
mysql_host = "127.0.0.1"
mysql_port = 3306
mysql_url_format = "mysql+pymysql://root:123456@%s:%s/%s"
mysql_database_name = "aops_test"
engine_url = mysql_url_format % (mysql_host, mysql_port, mysql_database_name)
ENGINE = create_database_engine(engine_url, 100, 7200)
SESSION = scoped_session(sessionmaker(bind=ENGINE))


def setup_mysql_db():
    test_mysql_db.connect()
    # create all tables
    # create_utils_tables(Base, ENGINE)
    create_vul_tables(ENGINE)
    # add data
    test_mysql_db.add_user()
    test_mysql_db.add_hostgroup()
    test_mysql_db.add_host()
    test_mysql_db.add_cve()
    test_mysql_db.add_repo()
    test_mysql_db.add_task()
    test_mysql_db.add_cve_task_info()
    test_mysql_db.add_cve_host_match()
    test_mysql_db.add_task_cve_host()
    test_mysql_db.add_task_repo_host()
    test_mysql_db.add_cve_pkgs()


def tear_down_mysql_db():
    test_mysql_db.close()
    drop_tables(Base, ENGINE)


def setup_es_db():
    test_es_db.connect()
    for index in MAPPINGS.keys():
        test_es_db.delete_index(index)
    for index, mapping in MAPPINGS.items():
        test_es_db.create_index(index, mapping)

    test_es_db.add_task_result()
    test_es_db.add_cve_pkg_info()
    sleep(1)


def tear_down_es_db():
    for index in MAPPINGS.keys():
        test_es_db.delete_index(index)
    test_es_db.close()
