"""
Author:         Nacho Pobes
Student number: 500855533
Name:           RepChecker
Version:        1.0
"""

import socket
import ipaddress

from mvc.exceptions import *


class ReputationCheckerModel:
    """Hold the model data.

    Attributes:
        fqdn (str): the FQDN used to retrieve reputation data
        ip_address (str): the IP address used to retrieve reputation data
        reputation_data (dict): the collected reputation data
    """

    def __init__(self):
        self._fqdn = None
        self._ip_address = None
        self.reputation_data = {}

    @property
    def fqdn(self):
        """ Access method for the fqdn attribute.

        Returns:
            fqdn (str): the FQDN used to retrieve reputation data
        """
        return self._fqdn

    @fqdn.setter
    def fqdn(self, fqdn):
        """ Setter method for the fqdn attribute.

        Args:
            fqdn (str): the FQDN input to retrieve reputation data

        Raises:
            OSError: Problem by resolving to an IP address
        """
        self._fqdn = fqdn
        try:
            ip_address = socket.gethostbyname(fqdn)
            self._ip_address = ip_address
        except OSError:
            raise

    @property
    def ip_address(self):
        """ Access method for the ip_address attribute.

        Returns:
            fqdn (str): the FQDN used to retrieve reputation data
        """
        return self._ip_address

    @ip_address.setter
    def ip_address(self, ip_address):
        """ Setter method for the ip_address attribute.

        Args:
            ip_address (str): the IP address to retrieve reputation data

        Raises:
            IpIsUnknownTypeError: Type IP address is unknown
            IpIsLoopbackError: IP address is loopback
            IpIsMulticastError: IP address is multicast
            IpIsLinkLocalError: IP address is link-local
            IpIsReservedError: IP address is IETF reserved
            IpIsUnspecifiedError: IP address is unspecified
            IpIsPrivateError: IP address is private
        """
        value = ipaddress.ip_address(ip_address)
        if (isinstance(value, ipaddress.IPv4Address)):
            ip_info = ipaddress.IPv4Address(ip_address)
        elif (isinstance(value, ipaddress.IPv6Address)):
            ip_info = ipaddress.IPv6Address(ip_address)
        else:
            raise IpIsUnknownTypeError

        if (ip_info.is_loopback):
            raise IpIsLoopbackError
        elif (ip_info.is_multicast):
            raise IpIsMulticastError
        elif (ip_info.is_link_local):
            raise IpIsLinkLocalError
        elif (ip_info.is_reserved):
            raise IpIsReservedError
        elif (ip_info.is_unspecified):
            raise IpIsUnspecifiedError
        elif (ip_info.is_private):
            raise IpIsPrivateError
        else:
            self._ip_address = ip_address

    def load_reputation_data(self, data):
        """ Load collected reputation data into model.

        Args:
            data (dict): the collected reputation data
        """
        try:
            network = data["virustotal_ip_data"]["data"]["attributes"]["network"]
        except KeyError:
            network = None
        self.reputation_data["general_information"] = {
            "network": network,
            "isp": data["abuseipdb_data"]["data"]["isp"],
            "country": data["geo_data"]["country_name"],
            "continent": data["geo_data"]["continent_name"],
            "registry": data["virustotal_ip_data"]["data"]["attributes"]["regional_internet_registry"]
        }
        self.reputation_data["abuseipdb"] = {
            "abuse_confidence": int(data["abuseipdb_data"]["data"]["abuseConfidenceScore"]),
            "total_reports": int(data["abuseipdb_data"]["data"]["totalReports"]),
            "total_users": int(data["abuseipdb_data"]["data"]["numDistinctUsers"]),
            "report_date": data["abuseipdb_data"]["data"]["lastReportedAt"]
        }
        self.reputation_data["virustotal"] = {
            "malicious_stats": int(data["virustotal_ip_data"]["data"]["attributes"]["last_analysis_stats"]["malicious"]),
            "suspicious_stats": int(data["virustotal_ip_data"]["data"]["attributes"]["last_analysis_stats"]["suspicious"]),
            "harmless_stats": int(data["virustotal_ip_data"]["data"]["attributes"]["last_analysis_stats"]["harmless"]),
            "report_date": data["virustotal_ip_data"]["data"]["attributes"]["last_modification_date"]
        }

    def get_reputation_data(self):
        """ Access method for the reputation_data attribute.

        Returns:
            reputation_data (dict): the used reputation data
        """
        return self.reputation_data