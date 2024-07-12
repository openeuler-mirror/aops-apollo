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
import uuid

from sqlalchemy import Column
from sqlalchemy.ext.declarative import declarative_base
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

    cve_id = Column(String(20), primary_key=True)
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

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid1()))
    cve_id = Column(String(20))
    host_id = Column(String(36), index=True)
    affected = Column(Boolean)
    fixed = Column(Boolean)
    support_way = Column(String(20), default=None)
    fixed_way = Column(String(20), default=None)
    hp_status = Column(String(20))
    installed_rpm = Column(String(100))
    available_rpm = Column(String(100))
    cluster_id = Column(String(36), nullable=False)


class Repo(Base, MyBase):
    """
    Repo Table
    """

    __tablename__ = "repo"

    repo_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid1()))
    repo_name = Column(String(20), nullable=False)
    repo_attr = Column(String(20), nullable=False)
    repo_data = Column(String(512), nullable=False)
    cluster_id = Column(String(36), nullable=False)


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
    fix_type = Column(String(20))
    cluster_id = Column(String(36), nullable=False)
    username = Column(String(36), nullable=False)


class TaskHostRepoAssociation(Base, MyBase):
    """
    task, host and repo tables' association table, record repo, host and task's matching
    relationship for setting repo task
    """

    __tablename__ = "task_host_repo"

    task_id = Column(String(32), primary_key=True)
    host_id = Column(String(36), primary_key=True)
    host_name = Column(String(50), nullable=False)
    host_ip = Column(String(16), nullable=False)
    repo_id = Column(String(36), nullable=False)
    # status can be "unset", "set" and "running"
    status = Column(String(20))


class CveFixTask(Base, MyBase):
    """
    cve fix task info table
    """

    __tablename__ = "cve_fix_task"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid1()))
    task_id = Column(String(32))
    host_id = Column(String(36))
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

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid1()))
    task_id = Column(String(32))
    fix_task_id = Column(String(20), nullable=False)
    # rollback_type can be "hotpatch" and "coldpatch"
    rollback_type = Column(String(20))
    host_id = Column(String(36))
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
    task_id = Column(String(32))
    cve_id = Column(String(20))
    host_id = Column(String(36))
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
