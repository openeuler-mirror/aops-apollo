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
Description: For host related restful interfaces schema
"""
from marshmallow import Schema, fields, validate
from vulcanus.restful.serialize.validate import PaginationSchema

from apollo.conf.constant import CveSeverity


class ScanHostFilterSchema(Schema):
    """
    filter schema of host scanning interface
    """

    host_name = fields.String(required=False, validate=lambda s: len(s) != 0)
    host_group = fields.List(fields.String(validate=lambda s: len(s) != 0), required=False)
    repo = fields.List(fields.String(), required=False)
    status = fields.List(fields.String(validate=validate.OneOf(["scanning", "done"])), required=False)


class ScanHostSchema(Schema):
    """
    validators for parameter of /vulnerability/host/scan
    """

    host_list = fields.List(
        fields.String(validate=lambda s: 0 < len(s) <= 36, required=True), required=False, missing=[]
    )
    filter = fields.Nested(ScanHostFilterSchema, required=False)


class GetHostStatusSchema(Schema):
    """
    validators for parameter of /vulnerability/host/status/get
    """

    host_list = fields.List(fields.String(validate=lambda s: 0 < len(s) <= 36, required=True), required=True)


class GetHostListFilterSchema(Schema):
    """
    filter schema of host list getting interface
    """

    host_name = fields.String(required=False, validate=lambda s: 0 < len(s) <= 50)
    host_group_ids = fields.List(fields.String(validate=lambda s: 0 < len(s) <= 36), required=False)
    repo = fields.List(fields.String(validate=lambda s: 0 < len(s) <= 36), required=False)
    cluster_list = fields.List(fields.String(required=False, validate=lambda s: 0 < len(s) <= 36), required=False)


class GetHostListSchema(PaginationSchema):
    """
    validators for parameter of /vulnerability/host/list/get
    """

    sort = fields.String(required=False, validate=validate.OneOf(["last_scan"]))
    direction = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))
    filter = fields.Nested(GetHostListFilterSchema, required=False)


class GetHostInfoSchema(Schema):
    """
    validators for parameter of /vulnerability/host/info/get
    """

    host_id = fields.String(validate=lambda s: 0 < len(s) <= 36, required=True)


class HostCvesFilterSchema(Schema):
    """
    filter schema of host's cve list getting interface
    """

    search_key = fields.String(required=False, validate=lambda s: 0 < len(s) <= 40)
    severity = fields.List(fields.String(validate=validate.OneOf(CveSeverity.attribute())), required=False)
    affected = fields.Boolean(required=False, default=True)
    fixed = fields.Boolean(validate=validate.OneOf([True, False]))


class GetHostCvesSchema(PaginationSchema):
    """
    validators for parameter of /vulnerability/host/cve/get
    """

    host_id = fields.String(validate=lambda s: 0 < len(s) <= 36, required=True)
    sort = fields.String(required=False, validate=validate.OneOf(["publish_time", "cvss_score"]))
    direction = fields.String(required=False, validate=validate.OneOf(["asc", "desc"]))
    filter = fields.Nested(HostCvesFilterSchema, required=False)
