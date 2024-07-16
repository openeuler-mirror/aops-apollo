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
Description: Manager that starts aops-manager
"""
try:
    from gevent import monkey

    monkey.patch_all()
except:
    pass

from vulcanus import init_application
from vulcanus.timed import TimedTaskManager
from vulcanus.log.log import LOGGER
from vulcanus.database.proxy import ElasticsearchProxy
from apollo.cron import task_meta
from apollo.conf.constant import TIMED_TASK_CONFIG_PATH
from apollo.database.mapping import MAPPINGS
from apollo.conf import configuration
from apollo.url import URLS


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
    config = {"max_result_window": configuration.elasticsearch.get('MAX_ES_QUERY_NUM')}
    proxy.update_settings(**config)


def _init_timed_task(application):
    """
    Initialize and create a scheduled task

    Args:
        application:flask.Application
    """
    timed_task = TimedTaskManager(app=application, config_path=TIMED_TASK_CONFIG_PATH)
    if not timed_task.timed_config:
        LOGGER.warning("If you want to start a scheduled task, please add a timed config.")
        return

    for task_info in timed_task.timed_config.values():
        task_type = task_info.get('type')
        if task_type not in task_meta:
            continue
        meta_class = task_meta[task_type]
        timed_task.add_job(meta_class(timed_config=task_info))

    timed_task.start()


def main():
    """
    Service initialization
    """
    _app = init_application(name="apollo", settings=configuration, register_urls=URLS)

    _init_elasticsearch()
    _init_timed_task(application=_app)
    return _app


app = main()


if __name__ == "__main__":
    app.run(host=configuration.apollo.get("IP"), port=configuration.apollo.get("PORT"))
