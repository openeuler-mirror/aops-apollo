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
from io import BytesIO, StringIO

from flask import Response

from apollo.conf.constant import TEMPLATE_REPO_STR


def get_template_stream_response(file_name="template.repo"):
    """
    Get yum repo template byte io stream and convert it to restful response
    Args:
        file_name (str): downloaded file's name

    Returns:

    """
    response = Response(string_iterator(TEMPLATE_REPO_STR))
    response.headers['Content-Type'] = "application/octet-stream"
    response.headers['Content-Disposition'] = "application;file_name='{}'".format(file_name)
    return response


def byte_iterator(input_str, chunk_size=512):
    """
    byte io stream
    Args:
        input_str (str): the string to convert to byte stream
        chunk_size (int): stream size of each read

    Returns:
        None
    """
    byte_io = BytesIO(bytes(input_str, encoding="utf8"))
    while True:
        chunk = byte_io.read(chunk_size)
        if chunk:
            yield chunk
        else:
            break


def string_iterator(input_str, chunk_size=512):
    """
    string io stream
    Args:
        input_str (str): the string to convert to byte stream
        chunk_size (int): stream size of each read

    Returns:
        None
    """
    string_io = StringIO(input_str)
    while True:
        chunk = string_io.read(chunk_size)
        if chunk:
            yield chunk
        else:
            break


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
