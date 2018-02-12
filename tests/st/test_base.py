# Copyright (c) 2017 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
from unittest import TestCase

from tests.st.utils.utils import (get_ip, wipe_etcdv2, wipe_etcdv3,
                                  set_version_etcdv2, set_ready_etcdv2, get_value_etcdv2)

HOST_IPV4 = get_ip()

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)


class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """

    def setUp(self):
        """
        Clean up before every test.
        """
        self.ip = HOST_IPV4
        self.wipe_etcdv2()
        self.wipe_etcdv3()
        minimum_starting_state()

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

    def wipe_etcdv2(self):
        wipe_etcdv2(self.ip)

    def wipe_etcdv3(self):
        wipe_etcdv3(self.ip)


def minimum_starting_state():
    logger.debug("INFO: Setting minimum starting state config for calicoctl v1")
    set_version_etcdv2("v2.6.6-2-g0f0e2184")
    set_ready_etcdv2("true")
    ready_output = get_value_etcdv2("/calico/v1/Ready")
    assert ready_output == "true"
