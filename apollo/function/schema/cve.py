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
Description: For cve related restful interfaces schema
"""
from marshmallow import Schema, fields, validate
from vulcanus.restful.serialize.validate import PaginationSchema

from apollo.conf.constant import CveSeverity


class CveListFilterSchema(Schema):
    """
    filter schema of cve list getting interface
    """

    search_key = fields.String(required=False, validate=lambda s: 0 < len(s) <= 40)
    severity = fields.List(fields.String(validate=validate.OneOf(CveSeverity.attribute())), required=False)
    affected = fields.Boolean(required=False, default=True)
    fixed = fields.Boolean(required=True, default=True, validate=validate.OneOf([True, False]))


class GetCveListSchema(PaginationSchema):
    """
    validators for parameter of /vulnerability/cve/list/get
    """

    sort = fields.String(required=False, validate=validate.OneOf(["cve_id", "publish_time", "cvss_score", "host_num"]))
    direction = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))
    filter = fields.Nested(CveListFilterSchema, required=False)


class GetCveInfoSchema(Schema):
    """
    validators for parameter of /vulnerability/cve/info/get
    """

    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)


class CveHostFilterSchema(Schema):
    """
    filter schema of cve host list getting interface
    """

    host_name = fields.String(required=False, validate=lambda s: len(s) != 0)
    host_group_ids = fields.List(fields.String(validate=lambda s: len(s) != 0), required=False)
    repo = fields.List(fields.String(validate=lambda s: len(s) != 0, allow_none=True), required=False)
    fixed = fields.Boolean(required=True, validate=validate.OneOf([True, False]))
    cluster_list = fields.List(fields.String(validate=lambda s: 0 < len(s) <= 36), required=False)


class GetCveHostsSchema(PaginationSchema):
    """
    validators for parameter of /vulnerability/cve/host/get
    """

    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    sort = fields.String(required=False, validate=validate.OneOf(["last_scan"]))
    direction = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))
    filter = fields.Nested(CveHostFilterSchema, required=False)


class PackageInfoSchema(Schema):
    """
    single package's info of a cve form
    """

    installed_rpm = fields.String(required=True, validate=lambda s: 0 < len(s) <= 100)
    available_rpm = fields.String(required=True, validate=lambda s: 0 < len(s) <= 100)
    fix_way = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)


class CveTaskHostSchemaOfCveInfo(Schema):
    """
    cve info schema for /vulnerability/cve/task/host/get
    """

    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    rpms = fields.List(fields.Nested(PackageInfoSchema), required=False, missing=[])


class GetCveTaskHostSchema(Schema):
    """
    validators for parameter of /vulnerability/cve/task/host/get
    """

    host_list = fields.List(fields.String(validate=lambda s: 0 < len(s) <= 36), required=False)
    cve_list = fields.List(fields.Nested(CveTaskHostSchemaOfCveInfo), required=True, validate=lambda s: len(s) != 0)
    fixed = fields.Boolean(required=True, default=False, validate=validate.OneOf([True, False]))


class CveBinaryPackageSchema(Schema):
    """
    validators for parameter of /vulnerability/cve/unfixed/packages/get or /vulnerability/cve/fixed/packages/get
    """

    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    host_ids = fields.List(fields.String(validate=lambda s: 0 < len(s) <= 36), required=False)


class GetGetCvePackageHostSchema(PaginationSchema):
    """
    validators for parameter of /vulnerability/cve/packages/host/get
    """

    direction = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))
    cve_id = fields.String(required=True, validate=lambda s: 0 < len(s) <= 20)
    installed_rpm = fields.String(required=True, validate=lambda s: 0 < len(s) <= 100)
    available_rpm = fields.String(required=False, validate=lambda s: 0 < len(s) <= 100)
    hp_status = fields.String(required=False, validate=lambda s: 0 < len(s) <= 20)
    fixed = fields.Boolean(required=True, default=False, validate=validate.OneOf([True, False]))
    host_ids = fields.List(fields.String(validate=lambda s: 0 < len(s) <= 36), required=False)


class ExportCveExcelSchema(Schema):
    host_list = fields.List(fields.String(validate=lambda s: 0 < len(s) <= 36), required=True)


class DownloadFileSchema(Schema):
    file_id = fields.String(validate=lambda s: 0 < len(s) <= 36, required=True)
