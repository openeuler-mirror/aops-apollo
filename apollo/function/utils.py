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
from typing import List
from urllib.parse import urlencode, quote

from flask import Response, g
from vulcanus.conf.constant import HOSTS_FILTER
from vulcanus.restful.resp import state
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration


def file_iterator(file_path, chunk_size=512):
    """
    file read iterator stream
    Args:
        file_path (str): file path
        chunk_size (int): stream size of each read

    Returns:
        None
    """
    with open(file_path, 'rb') as target_file:
        while True:
            chunk = target_file.read(chunk_size)
            if chunk:
                yield chunk
            else:
                break


def make_download_response(file_path: str, file_name: str) -> Response:
    """
    Create a download response for a given file.

    Args:
        file_path (str): The path to the file to be downloaded.
        file_name (str): The name of the file to be used in the download response.

    Returns:
        Response: A Flask response object for the file download.
    """
    safe_file_name = quote(file_name)
    response = Response(file_iterator(file_path))
    response.headers['Content-Type'] = "application/octet-stream"
    response.headers['Content-Disposition'] = f'attachment;filename="{safe_file_name}"'
    return response


def query_user_hosts(host_list: List[str] = None, fields: List[str] = None, **kwargs):
    """
    Query all host info held by the user

    Args:
        host_list (list): host id list
        fields (list): host info fields, support fields: host_id, host_name, host_ip, host_group_name,
                status, reboot,last_scan, repo_id, pkey, ssh_user, ssh_port, cluster_id
                default: host_id
        kwargs (dict): other query filters
    Returns:
        list:host id list
    """
    params = {"fields": ["host_id"]}
    params.update(kwargs)
    if host_list:
        params["host_ids"] = host_list

    if fields:
        params["fields"] = fields

    url = f"http://{configuration.domain}{HOSTS_FILTER}?{urlencode(params)}"
    response_data = BaseResponse.get_response(method="GET", url=url, header=g.headers)
    if response_data.get("label") != state.SUCCEED:
        return []

    if not fields:
        return [host_info.get("host_id") for host_info in response_data.get("data")]
    return response_data.get("data")
