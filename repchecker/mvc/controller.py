"""
Author:         Nacho Pobes
Student number: 500855533
Name:           RepChecker
Version:        1.0
"""
import re
import ipaddress
from urllib.error import URLError, HTTPError

from mvc.model import ReputationCheckerModel
from mvc.collector import ReputationCollector
from mvc.view import ReputationCheckerView
from mvc.exceptions import *


class ReputationCheckerController:
    """Control the application logic and the program flow.

    Attributes:
        view (object): reference to ReputationCheckerView
    """
    def __init__(self):
        self.view = ReputationCheckerView()

    def run(self):
        """Build the window and prepare it to receive input."""
        self.view.compose()
        self.view.activate(self.check_reputation)
        self.view.display()

    def check_reputation(self, key_event=None):
        """ Collect the data from the different sources.

        Args:
            key_event (object): key event received when pressing <Return> key; unused but necessary
        """
        self.view.reset_error()
        self.view.reset_reputation_data()
        input_value = self.view.get_input_value()
        is_valid_fqdn = self._is_valid_fqdn(input_value)
        is_valid_ip_address = self._is_valid_ip_address(input_value)
        if (is_valid_fqdn):
            try:
                model = ReputationCheckerModel()
                model.fqdn = input_value
                reputation_collector = ReputationCollector()
                model.load_reputation_data(reputation_collector.collect(model.ip_address, model.fqdn))
                self.view.show_reputation_data(model.ip_address, model.fqdn, model.get_reputation_data())
            except OSError:
                self.view.display_converting_fqdn_error()
        elif (is_valid_ip_address):
            try:
                model = ReputationCheckerModel()
                model.ip_address = input_value
                reputation_collector = ReputationCollector()
                model.load_reputation_data(reputation_collector.collect(model.ip_address))
                self.view.show_reputation_data(model.ip_address, model.fqdn, model.get_reputation_data())
            except IpIsUnknownTypeError:
                self.view.display_invalid_ip_error()
            except IpIsLoopbackError:
                self.view.display_is_loopback_error()
            except IpIsMulticastError:
                self.view.display_is_multicast_error()
            except IpIsLinkLocalError:
                self.view.display_is_link_local_error()
            except IpIsReservedError:
                self.view.display_is_reserved_error()
            except IpIsUnspecifiedError:
                self.view.display_is_unspecified_error()
            except IpIsPrivateError:
                self.view.display_is_private_error()
            except HTTPError as error:
                self.view.display_http_error(error.code)
            except URLError as error:
                self.view.display_url_error(error.reason)
        else:
            self.view.display_invalid_fqdn_ip_error()

    def _is_valid_fqdn(self, input_value):
        """ Validate a value as a FQDN.

        Args:
            input_value (str): the value to be evaluated as a FQDN
        """
        # Pattern obtained from https://www.geeksforgeeks.org/how-to-validate-a-domain-name-using-regular-expression/
        pattern = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}"
        try:
            # Compile the pattern for subsequent checks
            regobject = re.compile(pattern)
            found = regobject.match(input_value)
            if (found != None):
                return True
            return False
        except Exception:
            self.view.display_fqdn_validation_error()
        return False

    def _is_valid_ip_address(self, input_value):
        """ Validate a value as a IP address.

        Args:
            input_value (str): the value to be evaluated as an IP address
        """
        try:
            ipaddress.ip_address(input_value)
            return True
        except ValueError:
            # A ValueError is raised if address does not represent a valid IPv4 or IPv6 address.
            # See: https://docs.python.org/3/library/ipaddress.html
            return False