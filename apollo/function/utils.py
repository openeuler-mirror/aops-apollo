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
from flask import Response


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


def make_download_response(file_path, file_name):
    response = Response(file_iterator(file_path))
    response.headers['Content-Type'] = "application/octet-stream"
    response.headers['Content-Disposition'] = "application;file_name='{}'".format(
        file_name)
    return response


class ConstantBase:
    """
        Base class for constant classes

        Note: The values of these attributes should be initialized in a subclass
    """

    @classmethod
    def get_attributes(cls):
        """
        output all attributes

        Returns:
            a list containing all attributes

        """
        return [attr for attr in dir(cls) if not callable(getattr(cls, attr)) and not attr.startswith("__")]

    @classmethod
    def get_attributes_values(cls):
        """
        output all values of attributes

        Returns:
            a list containing values of all attributes
        """
        return [
            getattr(cls, attr) for attr in dir(cls) if not callable(getattr(cls, attr)) and not attr.startswith("__")
        ]
