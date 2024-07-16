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
Description: Manager that start aops-manager
"""
try:
    from gevent import monkey

    monkey.patch_all()
except:
    pass
import _thread
import socket

from apollo.subscribe import TaskCallbackSubscribe

from apollo.conf import configuration
from apollo.conf.constant import TaskChannel
from apollo.database.mapping import MAPPINGS
from apollo.url import URLS
from vulcanus import init_application
from vulcanus.database.proxy import ElasticsearchProxy, RedisProxy
from vulcanus.log.log import LOGGER
from vulcanus.registry.register_service.zookeeper import ZookeeperRegisterCenter


def _init_elasticsearch():
    """
    Initialize elasticsearch index and add default task
    """

    proxy = ElasticsearchProxy()
    for index_name, body in MAPPINGS.items():
        res = proxy.create_index(index_name, body)
        if not res:
            raise ValueError("create elasticsearch index %s fail", index_name)

    LOGGER.info("create elasticsearch index succeed")
    # update es settings
    config = {"max_result_window": configuration.elasticsearch.max_es_query_num}
    proxy.update_settings(**config)


def register_service():
    """
    register service
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(('8.8.8.8', 80))
        ip_address = sock.getsockname()[0]
    finally:
        sock.close()

    register_center = ZookeeperRegisterCenter(hosts=f"{configuration.zookeeper.host}:{configuration.zookeeper.port}")
    if not register_center.connected:
        register_center.connect()

    service_data = {"address": ip_address, "port": configuration.uwsgi.port}

    LOGGER.info("register zeus-host-information service")
    if not register_center.register_service(service_name="apollo", service_info=service_data, ephemeral=True):
        raise RuntimeError("register apollo service failed")

    LOGGER.info("register apollo service success")


def main():
    """
    Service initialization
    """
    _app = init_application(name="apollo", settings=configuration, register_urls=URLS)

    _init_elasticsearch()
    register_service()
    _thread.start_new_thread(
        TaskCallbackSubscribe(
            subscribe_client=RedisProxy.redis_connect,
            channels=[
                TaskChannel.CVE_FIX_TASK,
                TaskChannel.CVE_SCAN_TASK,
                TaskChannel.CVE_ROLLBACK_TASK,
                TaskChannel.HOTPATCH_REMOVE_TASK,
                TaskChannel.REPO_SET_TASK,
                TaskChannel.CLUSTER_SYNCHRONIZE_CANCEL_TASK,
                TaskChannel.TIMED_SEND_NOTIFICATION,
                TaskChannel.TIMED_CORRECT_TASK,
                TaskChannel.TIMED_SCAN_TASK,
                TaskChannel.TIMED_DOWNLOAD_SA,
            ],
        )
    )
    return _app


app = main()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=configuration.uwsgi.port, debug=True)
