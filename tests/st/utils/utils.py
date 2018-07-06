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
import copy
import os
import socket
import sys
from datetime import datetime
from subprocess import CalledProcessError
from subprocess import check_output, STDOUT

import termios

import json
import logging
from pprint import pformat

import yaml
from deepdiff import DeepDiff

LOCAL_IP_ENV = "MY_IP"
LOCAL_IPv6_ENV = "MY_IPv6"
logger = logging.getLogger(__name__)

ETCD_SCHEME = os.environ.get("ETCD_SCHEME", "http")
ETCD_CA = os.environ.get("ETCD_CA_CERT_FILE", "")
ETCD_CERT = os.environ.get("ETCD_CERT_FILE", "")
ETCD_KEY = os.environ.get("ETCD_KEY_FILE", "")
ETCD_HOSTNAME_SSL = "etcd-authority-ssl"

API_VERSION = 'projectcalico.org/v3'
ERROR_CONFLICT = "update conflict"
NOT_FOUND = "resource does not exist"
NOT_NAMESPACED = "is not namespaced"
SET_DEFAULT = "Cannot set"
NOT_SUPPORTED = "is not supported on"
KUBERNETES_NP = "kubernetes network policies must be managed through the kubernetes API"


class CalicoctlOutput:
    """
    CalicoctlOutput contains the output from running a calicoctl command using
    the calicoctl function below.

    This class contains the command, output and error code (if it failed)
    along with YAML/JSON decoded output if the output could be decoded.
    """

    def __init__(self, command, output, error=None):
        self.command = command
        self.output = output
        self.error = error

        # Attempt to decode the output and store the output format.
        self.decoded, self.decoded_format = decode_json_yaml(self.output)

    def assert_data(self, data, fmt="yaml", text=None):
        """
        Assert the decoded output from the calicoctl command matches the
        supplied data and the expected decoder format.
        Args:
            data:   The data to compare
            fmt: The expected output format of the data.
            text:   (optional) Expected text in the command output.
        """
        self.assert_no_error(text)
        assert self.decoded is not None, "No value was decoded from calicoctl response."
        if isinstance(data, str):
            data, _ = decode_json_yaml(data)
            assert data is not None, "String data did not decode"

        if fmt is not None:
            assert fmt == self.decoded_format, "Decoded format is different. " \
                                                  "expect %s; got %s" % (
                                                   fmt, self.decoded_format)

        # Copy and clean the decoded data to allow it to be comparable.
        cleaned = clean_calico_data(self.decoded)

        assert cmp(cleaned, data) == 0, \
            "Items are not the same.  Difference is:\n %s" % \
            pformat(DeepDiff(cleaned, data), indent=2)

    def assert_empty_list(self, kind, fmt="yaml", text=None):
        """
        Assert the calicoctl command output an empty list of the specified
        kind.

        Args:
            kind:   The resource kind.
            fmt: The expected output format of the data.
            text:   (optional) Expected text in the command output.

        Returns:

        """
        data = make_list(kind, [])
        self.assert_data(data, fmt=fmt, text=text)

    def assert_list(self, kind, items, fmt="yaml", text=None):
        """
        Assert the calicoctl command output an empty list of the specified
        kind.

        Args:
            kind:   The resource kind.
            items:  A list of the items in the list.
            fmt: The expected output format of the data.
            text:   (optional) Expected text in the command output.

        Returns:

        """
        data = make_list(kind, items)
        self.assert_data(data, fmt=fmt, text=text)

    def assert_error(self, text=None):
        """
        Assert the calicoctl command exited with an error.
        Args:
            text:   (optional) Expected text in the command output.
        """
        assert self.error, "Expected error running command; \n" \
                           "command=" + self.command + "\noutput=" + self.output
        self.assert_output_contains(text)

    def assert_no_error(self, text=None):
        """
        Assert the calicoctl command did not exit with an error code.
        Args:
            text:   (optional) Expected text in the command output.
        """
        assert not self.error, "Expected no error running command; \n" \
                               "command=" + self.command + "\noutput=" + self.output

        # If text is supplied, assert it appears in the output
        if text:
            self.assert_output_contains(text)

    def check_reports(self, reports):
        """
        Checking for unexpected reports.
        """
        unexpected_report = False
        for report in reports:
            if report in self.output:
                unexpected_report = True
                file_output = open("/code/calico-upgrade-report/" + report, 'rU')
                file_output_lines = file_output.read()
                file_output.close()
                logger.debug("ERROR: Command generated a unexpected report:\n/code/calico-upgrade-report/%s" % report)
                print file_output_lines
        if unexpected_report:
            logger.debug("ERROR: Unexpected report output displayed above.")

    def assert_output_contains(self, text):
        """
        Assert the calicoctl command output contains the supplied text.
        Args:
            text:   (optional) Expected text in the command output.
        """
        if not text:
            return
        assert text in self.output, "Expected text in output; \n" + \
                                    "command=" + self.command + "\noutput=\n" + self.output + \
                                    "\nexpected=\n" + text


def calicoctl(command, data=None):
    """
    Convenience function for abstracting away calling the calicoctl
    command.

    :param command:  The calicoctl command line parms as a single string.
    :param data:  Input data either as a string or a JSON serializable Python
    object.
    :return: The output from the command with leading and trailing
    whitespace removed.
    """
    # If input data is specified, save it to file in the required format.
    option_file = ''

    if data:
        writejson("/tmp/input-data", data)
        option_file = ' -f /tmp/input-data'

    calicoctl_bin = os.environ.get("CALICOCTL", "/code/dist/calicoctl")

    if ETCD_SCHEME == "https":
        etcd_auth = "%s:2379" % ETCD_HOSTNAME_SSL
    else:
        etcd_auth = "%s:2379" % get_ip()

    # Export the environment, in case the command has multiple parts, e.g.
    # use of | or ;
    #
    # Pass in all etcd params, the values will be empty if not set anyway
    calicoctl_env_cmd = "export ETCD_ENDPOINTS=%s; " \
                        "export ETCD_CA_CERT_FILE=%s; " \
                        "export ETCD_CERT_FILE=%s; " \
                        "export ETCD_KEY_FILE=%s; " \
                        "export DATASTORE_TYPE=%s; %s" % \
                        (ETCD_SCHEME + "://" + etcd_auth, ETCD_CA, ETCD_CERT, ETCD_KEY,
                         "etcdv3", calicoctl_bin)
    full_cmd = calicoctl_env_cmd + " " + command + option_file

    try:
        output = log_and_run(full_cmd)
        return CalicoctlOutput(full_cmd, output)
    except CalledProcessError as e:
        return CalicoctlOutput(full_cmd, e.output, error=e.returncode)


def calicoctlv2(command, data=None):
    """
    Convenience function for abstracting away calling the calicoctl
    command.

    :param command:  The calicoctl command line parms as a single string.
    :param data:  Input data either as a string or a JSON serializable Python
    object.
    :return: The output from the command with leading and trailing
    whitespace removed.
    """
    # If input data is specified, save it to file in the required format.
    option_file = ''

    if data:
        writejson("/tmp/input-data", data)
        option_file = ' -f /tmp/input-data'

    calicoctlv2_bin = os.environ.get("CALICOCTLV2", "/code/dist/calicoctlv2")

    if ETCD_SCHEME == "https":
        etcd_auth = "%s:2379" % ETCD_HOSTNAME_SSL
    else:
        etcd_auth = "%s:2379" % get_ip()

    # Export the environment, in case the command has multiple parts, e.g.
    # use of | or ;
    #
    # Pass in all etcd params, the values will be empty if not set anyway
    calicoctlv2_env_cmd = "export ETCD_ENDPOINTS=%s; " \
                          "export ETCD_CA_CERT_FILE=%s; " \
                          "export ETCD_CERT_FILE=%s; " \
                          "export ETCD_KEY_FILE=%s; " \
                          "export DATASTORE_TYPE=%s; %s" % \
                          (ETCD_SCHEME + "://" + etcd_auth, ETCD_CA, ETCD_CERT, ETCD_KEY,
                           "etcdv2", calicoctlv2_bin)

    if data:
        full_cmd = calicoctlv2_env_cmd + " " + command + option_file
    else:
        full_cmd = calicoctlv2_env_cmd + " " + command

    try:
        output = log_and_run(full_cmd)
        return CalicoctlOutput(full_cmd, output)
    except CalledProcessError as e:
        return CalicoctlOutput(full_cmd, e.output, error=e.returncode)


def calicoupgrade(command, prompt_resp='yes'):
    """
    Convenience function for abstracting away calling the calicoctl-upgrade
    command.

    :param command:  The calicoctl-upgrade command line parms as a single string.

    :return: The output from the command with leading and trailing
    whitespace removed.
    """

    calicoupgrade_bin = os.environ.get("CALICOUPGRADE", "/code/dist/calico-upgrade")

    if ETCD_SCHEME == "https":
        etcd_auth = "%s:2379" % ETCD_HOSTNAME_SSL
    else:
        etcd_auth = "%s:2379" % get_ip()

    # Calculate the full calico-upgrade command.
    if command != "dry-run":
        if not prompt_resp:
            # This is not a dry-run command and we are not passing in a prompt response.  In
            # this case we need to include the "--no-prompt" flag.
            command = calicoupgrade_bin + " " + command + " --no-prompt"
        else:
            # This is not a dry-run command, and we are including a prompt response.  Feed in
            # in the response using echo.
            command = "echo '%s' | %s %s" % (prompt_resp, calicoupgrade_bin, command)
    else:
        command = calicoupgrade_bin + " " + command

    # Export the environment, in case the command has multiple parts, e.g.
    # use of | or ;
    #
    # Pass in all etcd params, the values will be empty if not set anyway
    full_cmd = "export ETCD_ENDPOINTS=%s; " \
        "export APIV1_ETCD_ENDPOINTS=%s; " \
        "export ETCD_CA_CERT_FILE=%s; " \
        "export ETCD_CERT_FILE=%s; " \
        "export ETCD_KEY_FILE=%s; " \
        "export DATASTORE_TYPE=%s; %s" % \
        (ETCD_SCHEME + "://" + etcd_auth, ETCD_SCHEME + "://" + etcd_auth,
         ETCD_CA, ETCD_CERT, ETCD_KEY,
         "etcdv3", command)

    try:
        output = log_and_run(full_cmd)
        return CalicoctlOutput(full_cmd, output)
    except CalledProcessError as e:
        return CalicoctlOutput(full_cmd, e.output, error=e.returncode)


def clean_calico_data(data, extra_keys_to_remove=None):
    """
    Clean the data returned from a calicoctl get command to remove empty
    structs, null values and non-configurable fields.  This makes comparison
    with the input data much simpler.

    Args:
        data: The data to clean.
        extra_keys_to_remove: more keys to remove if needed.

    Returns: The cleaned data.

    """
    new = copy.deepcopy(data)

    # Recursively delete empty structs / nil values and non-configurable
    # fields.
    def clean_elem(elem, extra_keys):
        if isinstance(elem, list):
            # Loop through each element in the list
            for i in elem:
                clean_elem(i, extra_keys)
        if isinstance(elem, dict):
            # Remove non-settable fields, and recursively clean each value of
            # the dictionary, removing nil values or values that are empty
            # dicts after cleaning.
            del_keys = ['creationTimestamp', 'resourceVersion', 'uid']
            if extra_keys is not None:
                for extra_key in extra_keys:
                    del_keys.append(extra_key)
            for k, v in elem.iteritems():
                clean_elem(v, extra_keys)
                if v is None or v == {}:
                    del_keys.append(k)
            for k in del_keys:
                if k in elem:
                    del (elem[k])

    clean_elem(new, extra_keys_to_remove)
    return new


def decode_json_yaml(value):
    try:
        decoded = json.loads(value)
        # fix the python datetime back into isoformat with empty timezone information
        decoded = find_and_format_creation_timestamp(decoded)
        return decoded, "json"
    except ValueError:
        pass
    try:
        decoded = yaml.safe_load(value)
        # fix the python datetime back into isoformat with empty timezone information
        decoded = find_and_format_creation_timestamp(decoded)
        return decoded, "yaml"
    except yaml.YAMLError:
        pass
    return None, None


def find_and_format_creation_timestamp(decoded):
    if 'items' in decoded:
        for i in xrange(len(decoded['items'])):
            decoded['items'][i] = format_creation_timestamp(decoded['items'][i])
    else:
        decoded = format_creation_timestamp(decoded)
    return decoded


def format_creation_timestamp(decoded):
    if (isinstance(decoded, dict) and
            ('metadata' in decoded) and
            ('creationTimestamp' in decoded['metadata'])):
        if isinstance(decoded['metadata']['creationTimestamp'], datetime):
            decoded['metadata']['creationTimestamp'] = decoded.get('metadata', {}).get(
                'creationTimestamp', datetime.utcnow()).isoformat() + 'Z'
    return decoded


def writeyaml(filename, data):
    """
    Converts a python dict to yaml and outputs to a file.
    :param filename: filename to write
    :param data: dictionary to write out as yaml
    """
    with open(filename, 'w') as f:
        text = yaml.dump(data, default_flow_style=False)
        logger.debug("Writing %s: \n%s" % (filename, text))
        f.write(text)


def writejson(filename, data):
    """
    Converts a python dict to json and outputs to a file.
    :param filename: filename to write
    :param data: dictionary to write out as json
    """
    with open(filename, 'w') as f:
        text = json.dumps(data,
                          sort_keys=True,
                          indent=2,
                          separators=(',', ': '))
        logger.debug("Writing %s: \n%s" % (filename, text))
        f.write(text)


def get_ip(v6=False):
    """
    Return a string of the IP of the hosts interface.
    Try to get the local IP from the environment variables.  This allows
    testers to specify the IP address in cases where there is more than one
    configured IP address for the test system.
    """
    env = LOCAL_IPv6_ENV if v6 else LOCAL_IP_ENV
    ip = os.environ.get(env)
    if not ip:
        logger.debug("%s not set; try to auto detect IP.", env)
        socket_type = socket.AF_INET6 if v6 else socket.AF_INET
        s = socket.socket(socket_type, socket.SOCK_DGRAM)
        remote_ip = "2001:4860:4860::8888" if v6 else "8.8.8.8"
        s.connect((remote_ip, 0))
        ip = s.getsockname()[0]
        s.close()
    else:
        logger.debug("Got local IP from %s=%s", env, ip)

    return ip


# Some of the commands we execute like to mess with the TTY configuration,
# which can break the output formatting. As a workaround, save off the
# terminal settings and restore them after each command.
_term_settings = termios.tcgetattr(sys.stdin.fileno())


def log_and_run(command, raise_exception_on_failure=True):
    def log_output(results):
        if results is None:
            logger.info("  # <no output>")

        lines = results.split("\n")
        for line in lines:
            logger.info("  # %s", line.rstrip())

    try:
        logger.info("%s", command)
        try:
            results = check_output(command, shell=True, stderr=STDOUT).rstrip()
        finally:
            # Restore terminal settings in case the command we ran manipulated
            # them. Note: under concurrent access, this is still not a perfect
            # solution since another thread's child process may break the
            # settings again before we log below.
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _term_settings)
        log_output(results)
        return results
    except CalledProcessError as e:
        # Wrap the original exception with one that gives a better error
        # message (including command output).
        logger.info("  # Return code: %s", e.returncode)
        log_output(e.output)
        if raise_exception_on_failure:
            raise e


def curl_etcd(path, options=None, recursive=True, ip=None):
    """
    Perform a curl to etcd, returning JSON decoded response.
    :param path:  The key path to query
    :param options:  Additional options to include in the curl
    :param recursive:  Whether we want recursive query or not
    :param ip: IP address of etcd
    :return:  The JSON decoded response.
    """
    if options is None:
        options = []
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        rc = check_output(
            "curl --cacert %s --cert %s --key %s "
            "-sL https://%s:2379/v2/keys/%s?recursive=%s %s"
            % (ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL,
               path, str(recursive).lower(), " ".join(options)),
            shell=True)
    else:
        rc = check_output(
            "curl -sL http://%s:2379/v2/keys/%s?recursive=%s %s"
            % (ip, path, str(recursive).lower(), " ".join(options)),
            shell=True)

    return json.loads(rc.strip())


def wipe_etcdv2(ip):
    # Delete /calico if it exists. This ensures each test has an empty data
    # store at start of day.
    curl_etcd("calico", options=["-XDELETE"], ip=ip)

    # Disable Usage Reporting to usage.projectcalico.org
    # We want to avoid polluting analytics data with unit test noise
    curl_etcd("calico/v1/config/UsageReportingEnabled",
              options=["-XPUT -d value=False"], ip=ip)


def wipe_etcdv3(ip):
    # Delete /calico if it exists. This ensures each test has an empty data
    # store at start of day.
    curl_etcd("calico", options=["-XDELETE"], ip=ip)

    # Disable Usage Reporting to usage.projectcalico.org
    # We want to avoid polluting analytics data with unit test noise
    curl_etcd("calico/v1/config/UsageReportingEnabled",
              options=["-XPUT -d value=False"], ip=ip)

    etcd_container_name = "calico-etcd"
    tls_vars = ""
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        etcd_container_name = "calico-etcd-ssl"
        tls_vars = ("ETCDCTL_CACERT=/etc/calico/certs/ca.pem " +
                    "ETCDCTL_CERT=/etc/calico/certs/client.pem " +
                    "ETCDCTL_KEY=/etc/calico/certs/client-key.pem ")

    check_output("docker exec " + etcd_container_name + " sh -c '" + tls_vars +
                 "ETCDCTL_API=3 etcdctl del --prefix /calico" +
                 "'", shell=True)


def etcd_get_version(ip):
    # Delete /calico if it exists. This ensures each test has an empty data
    # store at start of day.
    curl_etcd("calico", options=["-XDELETE"], ip=ip)

    # Disable Usage Reporting to usage.projectcalico.org
    # We want to avoid polluting analytics data with unit test noise
    curl_etcd("/calico/v1/config/CalicoVersion",
              options=["-XPUT -d value=False"], ip=ip)


def set_version_etcdv2(calico_v1_ver):
    etcd_container_name = "calico-etcd"
    tls_vars = ""
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        etcd_container_name = "calico-etcd-ssl"
        tls_vars = ("ETCDCTL_CACERT=/etc/calico/certs/ca.pem " +
                    "ETCDCTL_CERT=/etc/calico/certs/client.pem " +
                    "ETCDCTL_KEY=/etc/calico/certs/client-key.pem ")

    log_and_run("docker exec " + etcd_container_name + " sh -c '" + tls_vars +
                "ETCDCTL_API=2 etcdctl set /calico/v1/config/CalicoVersion " + calico_v1_ver +
                "'")

    check_version_cmd = "docker exec " + etcd_container_name + " sh -c '" + tls_vars + \
                        "ETCDCTL_API=2 etcdctl get /calico/v1/config/CalicoVersion " + "'"

    output = log_and_run(check_version_cmd)

    if calico_v1_ver == output:
        logger.debug(
            "/calico/v1/config/CalicoVersion set=%s and get=%s\n" % (calico_v1_ver, output))
        return
    else:
        assert calico_v1_ver == output


def set_ready_etcdv2(flag_value):
    etcd_container_name = "calico-etcd"
    tls_vars = ""
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        etcd_container_name = "calico-etcd-ssl"
        tls_vars = ("ETCDCTL_CACERT=/etc/calico/certs/ca.pem " +
                    "ETCDCTL_CERT=/etc/calico/certs/client.pem " +
                    "ETCDCTL_KEY=/etc/calico/certs/client-key.pem ")

    log_and_run("docker exec " + etcd_container_name + " sh -c '" + tls_vars +
                "ETCDCTL_API=2 etcdctl set /calico/v1/Ready " + flag_value +
                "'")

    check_version_cmd = "docker exec " + etcd_container_name + " sh -c '" + tls_vars + \
                        "ETCDCTL_API=2 etcdctl get /calico/v1/Ready" + "'"

    output = log_and_run(check_version_cmd)
    if flag_value == output:
        logger.debug("/calico/v1/Ready set=%s and get=%s\n" % (flag_value, output))
        return
    else:
        assert flag_value == output


def get_value_etcdv2(flag_key):
    etcd_container_name = "calico-etcd"
    tls_vars = ""
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        etcd_container_name = "calico-etcd-ssl"
        tls_vars = ("ETCDCTL_CACERT=/etc/calico/certs/ca.pem " +
                    "ETCDCTL_CERT=/etc/calico/certs/client.pem " +
                    "ETCDCTL_KEY=/etc/calico/certs/client-key.pem ")

    get_value_cmd = "docker exec " + etcd_container_name + " sh -c '" + tls_vars + \
                    "ETCDCTL_API=2 etcdctl get " + flag_key + "'"

    output = log_and_run(get_value_cmd)
    return output


def dump_etcdv2():
    etcd_container_name = "calico-etcd"
    tls_vars = ""
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        etcd_container_name = "calico-etcd-ssl"
        tls_vars = ("ETCDCTL_CACERT=/etc/calico/certs/ca.pem " +
                    "ETCDCTL_CERT=/etc/calico/certs/client.pem " +
                    "ETCDCTL_KEY=/etc/calico/certs/client-key.pem ")

    log_and_run("docker exec " + etcd_container_name + " sh -c '" + tls_vars +
                "ETCDCTL_API=2 etcdctl ls -r" +
                "'")


def etcdv2_edit(etcdcmd):
    etcd_container_name = "calico-etcd"
    tls_vars = ""
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        etcd_container_name = "calico-etcd-ssl"
        tls_vars = (",ETCDCTL_CACERT=/etc/calico/certs/ca.pem" +
                    ",ETCDCTL_CERT=/etc/calico/certs/client.pem" +
                    ",ETCDCTL_KEY=/etc/calico/certs/client-key.pem")

    log_and_run("docker exec --env ETCDCTL_API=2" + tls_vars + " " + etcd_container_name + 
                " etcdctl " + etcdcmd)


def get_value_etcdv3(flag_key):
    etcd_container_name = "calico-etcd"
    tls_vars = ""
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        etcd_container_name = "calico-etcd-ssl"
        tls_vars = ("ETCDCTL_CACERT=/etc/calico/certs/ca.pem " +
                    "ETCDCTL_CERT=/etc/calico/certs/client.pem " +
                    "ETCDCTL_KEY=/etc/calico/certs/client-key.pem ")

    output = log_and_run("docker exec " + etcd_container_name + " sh -c '" + tls_vars +
                         "ETCDCTL_API=3 etcdctl get --prefix " + flag_key +
                         "'")
    return output


def dump_etcdv3():
    etcd_container_name = "calico-etcd"
    tls_vars = ""
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        etcd_container_name = "calico-etcd-ssl"
        tls_vars = ("ETCDCTL_CACERT=/etc/calico/certs/ca.pem " +
                    "ETCDCTL_CERT=/etc/calico/certs/client.pem " +
                    "ETCDCTL_KEY=/etc/calico/certs/client-key.pem ")

    log_and_run("docker exec " + etcd_container_name + " sh -c '" + tls_vars +
                "ETCDCTL_API=3 etcdctl get --prefix /calico" +
                "'")


def make_list(kind, items):
    """
    Convert the list of resources into a single List resource type.
    Args:
        kind: Type of resource
        items: A list of the resources in the List object.

    Returns:
        List of resources
    """
    assert isinstance(items, list)
    if "List" not in kind:
        kind = kind + "List"
    data = {
        'kind': kind,
        'apiVersion': API_VERSION,
        'items': items,
    }
    return data


def name(data):
    """
    Returns the name of the resource in the supplied data
    Args:
        data: A dictionary containing the resource.

    Returns: The resource name.
    """
    return data['metadata']['name']
