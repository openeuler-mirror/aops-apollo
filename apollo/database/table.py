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
Description: mysql tables
"""
from sqlalchemy import Column, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql.sqltypes import Boolean, Integer, String, Text
from vulcanus.database.helper import create_tables

from apollo.database import ENGINE

Base = declarative_base()


class MyBase:  # pylint: disable=R0903
    """
    Class that provide helper function
    """

    def to_dict(self):
        """
        Transfer query data to dict

        Returns:
            dict
        """
        return {col.name: getattr(self, col.name) for col in self.__table__.columns}  # pylint: disable=E1101


class Host(Base, MyBase):  # pylint: disable=R0903
    """
    Host table
    """

    __tablename__ = "host"

    host_id = Column(Integer(), primary_key=True, autoincrement=True)
    host_name = Column(String(50), nullable=False)
    host_ip = Column(String(16), nullable=False)
    management = Column(Boolean, nullable=False)
    host_group_name = Column(String(20))
    repo_name = Column(String(20))
    last_scan = Column(Integer)
    scene = Column(String(255))
    os_version = Column(String(40))
    ssh_user = Column(String(40), default="root")
    ssh_port = Column(Integer(), default=22)
    pkey = Column(String(2048))
    status = Column(Integer(), default=2)

    user = Column(String(40), ForeignKey('user.username'))
    host_group_id = Column(Integer, ForeignKey('host_group.host_group_id'))

    host_group = relationship('HostGroup', back_populates='hosts')
    owner = relationship('User', back_populates='hosts')
    reboot = Column(Boolean, nullable=False)

    def __eq__(self, o):
        return self.user == o.user and (
            self.host_name == o.host_name or f"{self.host_ip}{self.ssh_port}" == f"{o.host_ip}{o.ssh_port}"
        )


class HostGroup(Base, MyBase):
    """
    Host group table
    """

    __tablename__ = "host_group"

    host_group_id = Column(Integer, autoincrement=True, primary_key=True)
    host_group_name = Column(String(20))
    description = Column(String(60))
    username = Column(String(40), ForeignKey('user.username'))

    user = relationship('User', back_populates='host_groups')
    hosts = relationship('Host', back_populates='host_group')

    def __eq__(self, o):
        return self.username == o.username and self.host_group_name == o.host_group_name


class User(Base, MyBase):  # pylint: disable=R0903
    """
    User Table
    """

    __tablename__ = "user"

    username = Column(String(40), primary_key=True)
    password = Column(String(255), nullable=False)
    email = Column(String(40))

    host_groups = relationship('HostGroup', order_by=HostGroup.host_group_name, back_populates='user')
    hosts = relationship('Host', back_populates='owner')


class Cve(Base, MyBase):
    """
    Cve table
    """

    __tablename__ = "cve"

    cve_id = Column(String(20), nullable=False, primary_key=True)
    publish_time = Column(String(20))
    severity = Column(String(20))
    cvss_score = Column(String(20))
    reboot = Column(Boolean)


class CveAffectedPkgs(Base, MyBase):
    """
    record the affected packages of cves. A cve may affect multiple packages.
    """

    __tablename__ = "cve_affected_pkgs"

    cve_id = Column(String(20), ForeignKey('cve.cve_id'), primary_key=True)
    package = Column(String(40), primary_key=True)
    package_version = Column(String(50), primary_key=True)
    os_version = Column(String(50), primary_key=True, index=True)
    affected = Column(Integer)


class CveHostAssociation(Base, MyBase):
    """
    cve and vulnerability_host tables' association table, record the cve and host matching
    relationship for fixing cve task
    """

    __tablename__ = "cve_host_match"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(20))
    host_id = Column(Integer, ForeignKey('host.host_id', ondelete="CASCADE"), index=True)
    affected = Column(Boolean)
    fixed = Column(Boolean)
    support_way = Column(String(20), default=None)
    fixed_way = Column(String(20), default=None)
    hp_status = Column(String(20))
    installed_rpm = Column(String(100))
    available_rpm = Column(String(100))
    host_user = Column(String(100))


class Repo(Base, MyBase):
    """
    Repo Table
    """

    __tablename__ = "repo"

    repo_id = Column(Integer, autoincrement=True, primary_key=True)
    repo_name = Column(String(20), nullable=False)
    repo_attr = Column(String(20), nullable=False)
    repo_data = Column(String(512), nullable=False)

    username = Column(String(40), ForeignKey('user.username'))


class Task(Base, MyBase):
    """
    Task info Table
    """

    __tablename__ = "vul_task"

    task_id = Column(String(32), primary_key=True, nullable=False)
    task_type = Column(String(20), nullable=False)
    description = Column(String(100), nullable=False)
    task_name = Column(String(50), nullable=False)
    latest_execute_time = Column(Integer)
    create_time = Column(Integer)
    host_num = Column(Integer)
    check_items = Column(String(32))
    accepted = Column(Boolean, default=False)
    takeover = Column(Boolean, default=False)
    username = Column(String(40), ForeignKey('user.username'))
    fix_type = Column(String(20))


class TaskHostRepoAssociation(Base, MyBase):
    """
    task, host and repo tables' association table, record repo, host and task's matching
    relationship for setting repo task
    """

    __tablename__ = "task_host_repo"

    task_id = Column(String(32), ForeignKey('vul_task.task_id', ondelete="CASCADE"), primary_key=True)
    host_id = Column(Integer, primary_key=True)
    host_name = Column(String(50), nullable=False)
    host_ip = Column(String(16), nullable=False)
    repo_name = Column(String(20), nullable=False)
    # status can be "unset", "set" and "running"
    status = Column(String(20))


class CveFixTask(Base, MyBase):
    """
    cve fix task info table
    """

    __tablename__ = "cve_fix_task"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(32), ForeignKey('vul_task.task_id', ondelete="CASCADE"))
    host_id = Column(Integer)
    host_ip = Column(String(16), nullable=False)
    host_name = Column(String(50))
    cves = Column(Text)
    installed_rpm = Column(String(100))
    available_rpm = Column(String(100))
    fix_way = Column(String(20))
    # status can be "running", "succeed", "fail", "unknown"
    status = Column(String(20), nullable=False)
    take_over_result = Column(Boolean)
    dnf_event_start = Column(Integer)
    dnf_event_end = Column(Integer)


class CveRollbackTask(Base, MyBase):
    """
    cve rollback task info table
    """

    __tablename__ = "cve_rollback_task"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(32), ForeignKey('vul_task.task_id', ondelete="CASCADE"))
    rollback_fix_task_id = Column(String(20), nullable=False)
    # rollback_type can be "hotpatch" and "coldpatch"
    rollback_type = Column(String(20))
    host_id = Column(Integer)
    host_ip = Column(String(16), nullable=False)
    host_name = Column(String(50), nullable=False)
    cves = Column(Text)
    installed_rpm = Column(String(100))
    target_rpm = Column(String(100))
    # status can be "running", "succeed", "fail", "unknown"
    status = Column(String(20), nullable=False)
    dnf_event_start = Column(Integer)
    dnf_event_end = Column(Integer)


class HotpatchRemoveTask(Base, MyBase):
    """
    hotpatch remove task info table
    """

    __tablename__ = "hotpatch_remove_task"
    task_cve_host_id = Column(String(32), primary_key=True)
    task_id = Column(String(32), ForeignKey('vul_task.task_id', ondelete="CASCADE"))
    cve_id = Column(String(20))
    host_id = Column(Integer)
    host_name = Column(String(50), nullable=False)
    host_ip = Column(String(16), nullable=False)
    # status can be "running", "succeed", "fail", "unknown"
    status = Column(String(20), nullable=False)


class AdvisoryDownloadRecord(Base, MyBase):
    """
    Download and parse advisory's record
    """

    __tablename__ = "parse_advisory_record"
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    advisory_year = Column(String(4), nullable=False)
    advisory_serial_number = Column(String(10), nullable=False)
    download_status = Column(Boolean)


def create_vul_tables(engine=ENGINE):
    """
    create vulnerability tables of apollo service
    Args:
        engine: mysql engine

    Returns:

    """
    # pay attention, the sequence of list is important. Base table need to be listed first.
    tables = [
        Cve,
        CveHostAssociation,
        Task,
        Repo,
        AdvisoryDownloadRecord,
        TaskHostRepoAssociation,
        CveRollbackTask,
        HotpatchRemoveTask,
        CveAffectedPkgs,
    ]
    tables_objects = [Base.metadata.tables[table.__tablename__] for table in tables]
    create_tables(Base, engine, tables=tables_objects)
