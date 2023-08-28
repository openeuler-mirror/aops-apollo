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
Description: For task related restful interfaces schema
"""
from marshmallow import Schema
from marshmallow import fields
from marshmallow import validate
from vulcanus.restful.serialize.validate import PaginationSchema

from apollo.conf.constant import TaskType, TaskStatus


class TaskListFilterSchema(Schema):
    """
    filter schema of task list getting interface
    """

    task_name = fields.String(required=False, validate=lambda s: 0 < len(s) <= 20)
    task_type = fields.List(fields.String(validate=validate.OneOf(TaskType.attribute())), required=False)


class GetTaskListSchema(PaginationSchema):
    """
    validators for parameter of /vulnerability/task/list/get
    """

    sort = fields.String(required=False, validate=validate.OneOf(["host_num", "create_time"]))
    direction = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))
    filter = fields.Nested(TaskListFilterSchema, required=False)


class GetTaskProgressSchema(Schema):
    """
    validators for parameter of /vulnerability/task/progress/get
    """

    task_list = fields.List(fields.String(), required=True)


class GetTaskInfoSchema(Schema):
    """
    validators for parameter of /vulnerability/task/info/get
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)


class CveHostInfoDictSchema(Schema):
    """
    single host's info of a cve from
    """

    host_id = fields.Integer(required=True, validate=lambda s: s > 0)
    host_name = fields.String(required=True, validate=lambda s: 0 < len(s) <= 50)
    host_ip = fields.IP(required=True)


class PackageInfoSchema(Schema):
    """
    single package's info of a cve from
    """

    installed_rpm = fields.String(required=True, validate=lambda s: 0 < len(s) <= 100)
    available_rpm = fields.String(required=True, validate=lambda s: 0 < len(s) <= 100)
    fix_way = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)


class CveInfoDictSchema(Schema):
    """
    single cve's info of cve task from /vulnerability/task/cve/generate
    """

    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    host_info = fields.List(fields.Nested(CveHostInfoDictSchema), required=True, validate=lambda s: len(s) > 0)
    rpms = fields.List(fields.Nested(PackageInfoSchema), required=False)


class GenerateCveTaskSchema(Schema):
    """
    validators for parameter of /vulnerability/task/cve/generate
    """

    task_name = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    description = fields.String(required=True, validate=lambda s: 0 < len(s) <= 50)
    accepted = fields.Boolean(required=True, validate=validate.OneOf([True, False]))
    check_items = fields.List(fields.String(required=True, validate=lambda s: 0 < len(s) <= 32), required=False)
    takeover = fields.Boolean(required=True, validate=validate.OneOf([True, False]))
    info = fields.List(fields.Nested(CveInfoDictSchema), required=True, validate=lambda s: len(s) > 0)


class CveTaskInfoFilterSchema(Schema):
    """
    filter schema of cve task info getting interface
    """

    cve_id = fields.String(required=False, validate=lambda s: 0 < len(s) <= 20)
    status = fields.List(fields.String(validate=validate.OneOf(TaskStatus.attribute())), required=False)


class GetCveTaskInfoSchema(PaginationSchema):
    """
    validators for parameter of /vulnerability/task/cve/info/get
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    sort = fields.String(required=False, validate=validate.OneOf(["host_num"]))
    direction = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))
    filter = fields.Nested(CveTaskInfoFilterSchema, required=False)


class GetCveTaskStatusSchema(Schema):
    """
    validators for parameter of /vulnerability/task/cve/status/get
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    cve_list = fields.List(fields.String(), required=True)


class GetCveTaskProgressSchema(Schema):
    """
    validators for parameter of /vulnerability/task/cve/progress/get
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    cve_list = fields.List(fields.String(), required=True)


class GetCveTaskResultSchema(Schema):
    """
    validators for parameter of /vulnerability/task/cve/result/get
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    cve_list = fields.List(fields.String(), required=True)


class RollbackCveTaskSchema(Schema):
    """
    validators for parameter of /vulnerability/task/cve/rollback
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    cve_list = fields.List(fields.String(), required=True)


class GenerateRepoTaskSchema(Schema):
    """
    validators for parameter of /vulnerability/task/repo/generate
    """

    task_name = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    description = fields.String(required=True, validate=lambda s: 0 < len(s) <= 50)
    repo_name = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    info = fields.List(fields.Nested(CveHostInfoDictSchema), required=True, validate=lambda s: len(s) > 0)


class RepoTaskInfoFilterSchema(Schema):
    """
    filter schema of repo task info getting interface
    """

    host_name = fields.String(required=False, validate=lambda s: 0 < len(s) <= 50)
    status = fields.List(fields.String(validate=validate.OneOf(TaskStatus.attribute())), required=False)


class GetRepoTaskInfoSchema(PaginationSchema):
    """
    validators for parameter of /vulnerability/task/repo/info/get
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    filter = fields.Nested(RepoTaskInfoFilterSchema, required=False)


class GetRepoTaskResultSchema(Schema):
    """
    validators for parameter of /vulnerability/task/repo/result/get
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    host_list = fields.List(fields.Integer(required=True, validate=lambda s: s > 0), required=True)


class ExecuteTaskSchema(Schema):
    """
    validators for parameter of /vulnerability/task/execute
    """

    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)


class DeleteTaskSchema(Schema):
    """
    validators for parameter of /vulnerability/task/delete
    """

    task_list = fields.List(fields.String(), required=True, validate=lambda s: len(s) != 0)


class PreCheckItemsResultSchema(Schema):
    item = fields.String(required=True, validate=lambda s: len(s) != 0)
    result = fields.Boolean(default=False)
    log = fields.String(required=True, validate=lambda s: len(s) != 0)


class CveFixPackageResultSchema(Schema):
    installed_rpm = fields.String(required=True, validate=lambda s: len(s) != 0)
    result = fields.String(required=True, validate=lambda s: len(s) != 0)
    log = fields.String(required=True, validate=lambda s: len(s) != 0)


class CveFixResultCallbackSchema(Schema):
    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    result = fields.String(required=True, validate=lambda s: len(s) != 0)
    rpms = fields.Nested(CveFixPackageResultSchema, many=True)


class CallbackSchma(Schema):
    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    host_id = fields.Integer(required=True, validate=lambda s: s > 0)
    host_ip = fields.IP(required=True)
    host_name = fields.String(required=True, validate=lambda s: 0 < len(s) <= 50)
    status = fields.String(required=True, validate=lambda s: len(s) != 0)
    execution_time = fields.Integer(required=True)


class CveFixCallbackSchema(CallbackSchma):
    check_items = fields.Nested(PreCheckItemsResultSchema, many=True)
    cves = fields.Nested(CveFixResultCallbackSchema, many=True)


class CheckItemsSchema(Schema):
    item = fields.String(required=True, validate=lambda s: len(s) != 0)
    result = fields.Boolean(validate=validate.OneOf([True, False]), required=True)
    log = fields.String(required=True, validate=lambda s: len(s) != 0)


class RepoSetCallbackSchema(Schema):
    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    host_id = fields.Integer(required=True, validate=lambda s: s > 0)
    host_ip = fields.IP(required=True)
    host_name = fields.String(required=True, validate=lambda s: 0 < len(s) <= 50)
    status = fields.String(required=True, validate=lambda s: len(s) != 0)
    execution_time = fields.Integer(required=True)
    repo_name = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    check_items = fields.List(fields.Nested(CheckItemsSchema(), required=False), required=False)
    log = fields.String(required=True, validate=lambda s: len(s) != 0)


class UnfixedCveInfoSchema(Schema):
    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    installed_rpm = fields.String(required=True, validate=lambda s: 0 <= len(s) <= 100)
    available_rpm = fields.String(required=True, validate=lambda s: 0 <= len(s) <= 100)
    support_way = fields.String(validate=validate.OneOf(["hotpatch", "coldpatch", ""]), required=True)


class InstallPcakageInfoSchema(Schema):
    name = fields.String(required=True, validate=lambda s: len(s) != 0)
    version = fields.String(required=True, validate=lambda s: len(s) != 0)


class FixedCveInfoSchema(Schema):
    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    installed_rpm = fields.String(required=True, validate=lambda s: 0 < len(s) <= 100)
    fix_way = fields.String(validate=validate.OneOf(["hotpatch", "coldpatch"]), required=True)
    hp_status = fields.String(validate=validate.OneOf(["ACCEPTED", "ACTIVED"]), required=False)


class CveScanCallbackSchema(Schema):
    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)
    host_id = fields.Integer(required=True, validate=lambda s: s > 0)
    status = fields.String(required=True, validate=lambda s: len(s) != 0)
    check_items = fields.List(fields.Nested(CheckItemsSchema(), required=False), required=False)
    installed_packages = fields.List(fields.Nested(InstallPcakageInfoSchema(), required=True), required=False)
    os_version = fields.String(required=False, validate=lambda s: 0 < len(s) < 40)
    unfixed_cves = fields.List(fields.Nested(UnfixedCveInfoSchema(), required=False), required=False)
    fixed_cves = fields.List(fields.Nested(FixedCveInfoSchema(), required=False), required=False)


class CveRollbackHostPatchInfoSchema(Schema):
    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    hotpatch = fields.Boolean()


class CveRollbackInfoSchema(Schema):
    host_id = fields.Integer(required=True, validate=lambda s: s > 0)
    cves = fields.List(fields.Nested(CveRollbackHostPatchInfoSchema), required=True, validate=lambda s: len(s) > 0)


class GenerateCveRollbackTaskSchema(Schema):
    task_name = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    description = fields.String(required=True, validate=lambda s: 0 < len(s) <= 50)
    info = fields.List(fields.Nested(CveRollbackInfoSchema), required=True, validate=lambda s: len(s) > 0)


class CveRollbackResultSchema(Schema):
    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    result = fields.String(required=True, validate=lambda s: len(s) != 0)
    log = fields.String(required=True, validate=lambda s: len(s) != 0)


class CveRollbackCallbackSchema(CallbackSchma):
    check_items = fields.Nested(PreCheckItemsResultSchema, many=True)
    cves = fields.Nested(CveRollbackResultSchema, many=True)


class TaskCveRpmInfoSchema(Schema):
    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    task_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 32)


__all__ = [
    'GetTaskListSchema',
    'GetTaskProgressSchema',
    'GetTaskInfoSchema',
    'GenerateCveTaskSchema',
    'GetCveTaskInfoSchema',
    'GetCveTaskStatusSchema',
    'GetCveTaskProgressSchema',
    'GetCveTaskResultSchema',
    'RollbackCveTaskSchema',
    'GenerateRepoTaskSchema',
    'GetRepoTaskInfoSchema',
    'GetRepoTaskResultSchema',
    'ExecuteTaskSchema',
    'DeleteTaskSchema',
    'CveFixCallbackSchema',
    'RepoSetCallbackSchema',
    'CveScanCallbackSchema',
    'GenerateCveRollbackTaskSchema',
    'CveRollbackCallbackSchema',
    'TaskCveRpmInfoSchema',
]
