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
import os
import zipfile

from vulcanus.log.log import LOGGER

__all__ = ["unzip", "compress_cve"]


def unzip(file_path, max_size=20 * 1024 * 1024, max_num=100):
    """
    unzip file
    Args:
        file_path (str): file's path
        max_size (int): unzipped files max size
        max_num (int): max number of unzipped files
    Returns:
        str: decompressed folder's path
    """
    try:
        srcfile = zipfile.ZipFile(file_path, 'r')
    except (FileNotFoundError, IsADirectoryError, zipfile.BadZipFile) as error:
        LOGGER.error(error)
        return ""

    file_num = len(srcfile.infolist())
    if file_num > max_num:
        os.remove(file_path)
        LOGGER.error("The number of decompressed file exceeds the limit: %d > %d" % (file_num, max_num))
        srcfile.close()
        return ""

    total_size = 0
    for info in srcfile.infolist():
        total_size += info.file_size
    if total_size > max_size:
        os.remove(file_path)
        LOGGER.error("The size of decompressed file exceeds the limit: %d > %d" % (total_size, max_size))
        srcfile.close()
        return ""

    folder_path = file_path + "_dir"

    if not os.path.isdir(folder_path):
        os.mkdir(folder_path)

    for info in srcfile.infolist():
        srcfile.extract(info.filename, folder_path)
    srcfile.close()
    os.remove(file_path)
    return folder_path


def compress_cve(cve_dir_path: str, zip_filename: str):
    """
    Compress the cve files folder
    Args:
        cve_dir_path: cve excel folder path
        zip_filename: cve zip filename
    Returns:
        str,str: zip filename, zip file's folder path
    """
    zip = zipfile.ZipFile(os.path.join(cve_dir_path, zip_filename), "w", zipfile.ZIP_DEFLATED)
    try:
        for path, dirnames, filenames in os.walk(cve_dir_path):
            for filename in filenames:
                suffix = filename.split('.')[-1]
                if suffix != "zip":
                    zip.write(os.path.join(path, filename), os.path.join(filename))
        zip.close()
        return zip_filename, cve_dir_path
    except zipfile.BadZipFile as error:
        LOGGER.error(error)
        zip.close()
        return "", ""
