# Copyright (c) 2015-2017 Tigera, Inc. All rights reserved.
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
import os

import json
import yaml
from nose_parameterized import parameterized
from nose.plugins.attrib import attr

from tests.st.test_base import TestBase
from tests.st.utils.utils import calicoctl, calicoctlv2, \
    name, dump_etcdv2, get_value_etcdv2, get_value_etcdv3, \
    calicoupgrade, wipe_etcdv2, get_ip, clean_calico_data
from tests.st.utils.v1_data import data

ETCD_SCHEME = os.environ.get("ETCD_SCHEME", "http")
ETCD_CA = os.environ.get("ETCD_CA_CERT_FILE", "")
ETCD_CERT = os.environ.get("ETCD_CERT_FILE", "")
ETCD_KEY = os.environ.get("ETCD_KEY_FILE", "")
ETCD_HOSTNAME_SSL = "etcd-authority-ssl"

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

CONVERT_ERROR_MSG = "ERROR: Error converting data, check output for details and resolve issues"


class TestCalicoUpgrade(TestBase):

    @parameterized.expand([
        ("bgppeer_long_node_name", False),
        ("bgppeer_dotted_asn", False),
        ("hep_tame", False),
        ("hep_mixed_ip", False),
        ("hep_long_fields", False),
        ("ippool_mixed", False),
        ("ippool_v4_small", False),
        ("ippool_v4_large", False),
        ("node_long_name", False),
        ("node_tame", False),
        ("policy_long_name", False),
        ("policy_big", False),
        ("policy_tame", False),
        ("profile_big", False),
        ("profile_tame", False),
        ("wep_lots_ips", False),
        ("wep_similar_name_2", False),
        ("do_not_track", False),
        ("prednat_policy", False),
    ])
    @attr('slow')
    def test_conversion(self, testname, fail_expected):
        """
        Test successful conversion of each resource, dry-run and start file validation.
        etcdv2 Ready and etcdv3 datastoreReady flag validation.

        Correctly converted data validated with calicoctlv3 get compared to
        calicoctl convert manifest output.
        """
        testdata = data[testname]
        report1 = "convertednames"

        calicoctlv2("create", data=testdata)
        logger.debug("INFO: dump of etcdv2:")
        dump_etcdv2()

        rcu = calicoupgrade("dry-run")
        logger.debug("INFO: calico-upgrade dry-run should return 0.")
        rcu.assert_no_error()

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "true"

        dr_report1 = _get_readlines(report1)
        logger.debug(
            "INFO: calico-upgrade dry-run %s output:\n%s" % (report1, dr_report1))

        rcu = calicoupgrade("start")
        logger.debug("INFO: calico-upgrade start should return 0.")
        rcu.assert_no_error()

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "false"

        datastore_ready_rc = _get_ready_etcdv3()
        assert datastore_ready_rc is False

        st_report1 = _get_readlines(report1)
        logger.debug(
            "INFO: calico-upgrade start %s output:\n%s" % (report1, st_report1))

        assert dr_report1 == st_report1, \
            "INFO: calico-upgrade dry-run and start %s files are not equal" % report1

        rcc = calicoctl("convert", data=testdata)
        rcc.assert_no_error()

        parsed_output = yaml.safe_load(rcc.output)
        converted_data = clean_calico_data(parsed_output)
        logger.debug("INFO: converted data to v3\n%s" % converted_data)
        original_resource = rcc

        rcc = calicoctl("get %s %s -o yaml" % (converted_data['kind'], name(converted_data)))
        logger.debug("INFO: calicoctl (v3) get - after calico-upgrade start: \n%s" % rcc.output)

        # Comparison here needs to be against cleaned versions of data to remove Creation Timestamp
        logger.debug("Comparing 'get'ted output with original converted yaml")
        cleaned_output = yaml.safe_dump(
            clean_calico_data(
                yaml.safe_load(rcc.output),
                extra_keys_to_remove=['projectcalico.org/orchestrator', 'namespace']
            )
        )
        original_resource.assert_data(cleaned_output)

        rcu = calicoupgrade("complete")
        logger.debug("INFO: calico-upgrade complete should return 0.")
        rcu.assert_no_error()

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "false"

        datastore_ready_rc = _get_ready_etcdv3()
        assert datastore_ready_rc is True

    @parameterized.expand([
        ("hep_bad_label", True, CONVERT_ERROR_MSG, "convertednames", "validationerrors"),
        ("hep_label_too_long", True, CONVERT_ERROR_MSG, "convertednames", "validationerrors"),
        ("hep_name_too_long", True, CONVERT_ERROR_MSG, "convertednames", "validationerrors"),
        ("wep_bad_workload_id", True, CONVERT_ERROR_MSG, "convertednames", "conversionerrors"),
        ("wep_similar_name", True, CONVERT_ERROR_MSG, "convertednames", "conversionerrors"),
        ("profile_long_labels", True, CONVERT_ERROR_MSG, "validationerrors"),
    ])
    def test_conversion_failure(self, testname, fail_expected, error_text, report1, report2=None):
        """
        Test failed conversion with dry-run and start file validation.
        etcdv2 Ready and etcdv3 datastoreReady flag validation.
        """

        testdata = data[testname]

        calicoctlv2("create", data=testdata)
        logger.debug("INFO: dump of etcdv2:")
        dump_etcdv2()

        rcu = calicoupgrade("dry-run")
        logger.debug("INFO: calico-upgrade dry-run should return non-zero.")
        rcu.assert_error(error_text)

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "true"

        dr_report1 = _get_readlines(report1)
        logger.debug(
            "INFO: calico-upgrade dry-run %s output:\n%s" % (report1, dr_report1))

        if report2 is not None:
            dr_report2 = _get_readlines(report2)
            logger.debug(
                "INFO: calico-upgrade dry-run %s output:\n%s" % (report2, dr_report2))

        rcu = calicoupgrade("start")
        logger.debug("INFO: calico-upgrade dry-run should return non-zero.")
        rcu.assert_error(error_text)

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "true"

        st_report1 = _get_readlines(report1)
        logger.debug(
            "INFO: calico-upgrade start %s output:\n%s" % (report1, st_report1))

        assert dr_report1 == st_report1, \
            "INFO: calico-upgrade dry-run and start %s files are not equal" % report1

        if report2 is not None:
            st_report2 = _get_readlines(report2)
            logger.debug(
                "INFO: calico-upgrade dry-run %s output:\n%s" % (report2, st_report2))
            assert dr_report2 == st_report2, \
                "INFO: calico-upgrade dry-run and start %s files are not equal" % report2

    @parameterized.expand([
        ("ippool_mixed", False),
        ("policy_long_name", False),
        ("profile_big", False),
    ])
    @attr('slow')
    def test_start_abort_ignore_v3_data(self, testname, fail_expected):
        """
        Test the abort command re-enables the v1 Ready flag.

        calico-upgrade abort - aborts the upgrade process
        by resuming Calico networking for the v2.x nodes.
        """
        testdata = data[testname]

        calicoctlv2("create", data=testdata)
        logger.debug("INFO: dump of etcdv2:")
        dump_etcdv2()

        rcu = calicoupgrade("start")
        logger.debug("INFO: calico-upgrade start should return 0.")
        rcu.assert_no_error()

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "false"

        datastore_ready_rc = _get_ready_etcdv3()
        assert datastore_ready_rc is False

        rcu = calicoupgrade("abort")
        logger.debug("INFO: calico-upgrade abort should return 0.")
        rcu.assert_no_error()

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "true"

        datastore_ready_rc = _get_ready_etcdv3()
        assert datastore_ready_rc is False

        rcu = calicoupgrade("start --ignore-v3-data")
        logger.debug("INFO: calico-upgrade start should return 0.")
        rcu.assert_no_error()

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "false"

        datastore_ready_rc = _get_ready_etcdv3()
        assert datastore_ready_rc is False

        rcu = calicoupgrade("complete")
        logger.debug("INFO: calico-upgrade complete should return 0.")
        rcu.assert_no_error()

        ready_output = get_value_etcdv2("/calico/v1/Ready")
        assert ready_output == "false"

        datastore_ready_rc = _get_ready_etcdv3()
        assert datastore_ready_rc is True


@parameterized.expand([
    "dry-run",
    "start",
])
def test_empty_datastore(cmd):
    """
    Test dry-run and start when the etcdv2 datastore is empty.
    """
    wipe_etcdv2(get_ip())
    dump_etcdv2()
    rcu = calicoupgrade(cmd)
    logger.debug("INFO: empty etcdv2 datastore: Expecting a non-zero"
                 + "return code for calico-upgrade %s.", cmd)
    rcu.assert_error()


def _get_readlines(file_generated):
    """
    Get the readlines() of the file generated.
    """
    file_output = open("/code/calico-upgrade-report/"+file_generated, 'rU')
    file_output_lines = file_output.readlines()
    file_output.close()
    return file_output_lines


def _get_ready_etcdv3():
    return_value = get_value_etcdv3(
        "/calico/resources/v3/projectcalico.org/clusterinformations/default"
        + " | grep -v /calico/resources/v3/projectcalico.org/clusterinformations/default")
    logger.debug(
        "INFO: value of /calico/resources/v3/projectcalico.org/clusterinformations/default\n%s"
        % return_value)
    decoded = json.loads(return_value)
    logger.debug(
        "INFO: etcdv3 datastoreReady flag is set to:\n%s" % decoded['spec']['datastoreReady'])
    return decoded['spec']['datastoreReady']
