#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
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
Description: manager configuration
"""
from vulcanus.cache import RedisCacheManage, RedisProxy
from vulcanus.conf import ConfigHandle

from apollo.conf import default_config

# read manager configuration
config_obj = ConfigHandle("aops-apollo", default_config)
configuration = config_obj.parser

if RedisProxy.redis_connect is None:
    RedisProxy()
cache = RedisCacheManage(configuration.domain, RedisProxy.redis_connect)
