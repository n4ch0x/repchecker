"""
Author:         Nacho Pobes
Student number: 500855533
Name:           RepChecker
Version:        1.0
"""
import urllib.request, urllib.parse
from urllib.error import URLError, HTTPError
import json


class ReputationCollector:
    """Collect reputation and geographic information based on a FQDN of IP address from IPStack, AbuseIPDB and
    VirusTotal.

    Attributes:
        data (dict): to store all collected data
    """

    def __init__(self):
        self.data = {}

    def collect(self, ip_address, fqdn=None):
        """ Collect the data from the different sources.

        Args:
            ip_address (str): the IP address used to query the sources
            fqdn (str): the FQDN used to query the sources, if present

        Returns:
            data (dict): the collected data
        """
        self.data["geo_data"] = self._collect_geo_data(ip_address)
        self.data["abuseipdb_data"] = self._collect_abuseipdb_data(ip_address)
        url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip_address
        self.data["virustotal_ip_data"] = self._collect_virustotal_data(url)
        if (fqdn != None):
            url = 'https://www.virustotal.com/api/v3/domains/' + fqdn
            self.data["virustotal_fqdn_data"] = self._collect_virustotal_data(url)
        return self.data

    def _collect_geo_data(self, ip_address):
        """ Collect the geographic data from IPStack API.

        Args:
            ip_address (str): the IP address used to query the source

        Raises:
            HTTPError: Web server problem
            URLError: Connection problem
        """
        api_key = "0b4cfa94316947a83f384628673d2b03"
        url = 'http://api.ipstack.com/' + ip_address + "?access_key=" + api_key
        try:
            request = urllib.request.Request(url)
            request.add_header("Accept", "application/json")
            response = urllib.request.urlopen(request)
            data = json.loads(response.read())
            return data
        except HTTPError:
            raise
        except URLError:
            raise

    def _collect_abuseipdb_data(self, ip_address):
        """ Collect the abuse data from AbuseIPDB API.

        Args:
            ip_address (str): the IP address used to query the source

        Raises:
            HTTPError: Web server problem
            URLError: Connection problem
        """
        api_key = 'a2534807b8b0a5a79072839dcae54e65dd999d9273553bfca05c094a073c11972aed748682c23b83'
        url = 'https://api.abuseipdb.com/api/v2/check'
        try:
            parameters = urllib.parse.urlencode({'ipAddress': ip_address, 'maxAgeInDays': '90'})
            request = urllib.request.Request(url + "?" + parameters)
            request.add_header("Accept", "application/json")
            request.add_header("Key", api_key)
            response = urllib.request.urlopen(request)
            data = json.loads(response.read())
            return data
        except HTTPError:
            raise
        except URLError:
            raise

    def _collect_virustotal_data(self, url):
        """ Collect the reputation data from VirusTotal API.

        Args:
            url (str): the URL where the API resides

        Raises:
            HTTPError: Web server problem
            URLError: Connection problem
        """
        api_key = 'ca5711c3d4c41c29397add417497a259014953ef1c4c3765e8b51ade431a2b48'
        try:
            request = urllib.request.Request(url)
            request.add_header("Accept", "application/json")
            request.add_header("X-Apikey", api_key)
            response = urllib.request.urlopen(request)
            data = json.loads(response.read())
            return data
        except HTTPError:
            raise
        except URLError:
            raise