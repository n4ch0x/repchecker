"""
Author:         Nacho Pobes
Student number: 500855533
Name:           RepChecker
Version:        1.0
Input:          A string containing a FQDN or an IP address
Output:         Reputation values for the given FQDN or IP address according to AbuseIPDB and VirusTotal
Description:    This application displays the reputation of a given FQDN or IP address as indicated by
                the AbuseIPDB and VirusTotal databases as well as geographic information about the used FQDN or IP
                address according to IPStack. The values are obtained querying their respective API's.
                The displayed data can be used to evaluate a FQDN or IP address on e-mail headers or firewall logs.
                The application follows an MVC architecture in order to ensure data encapsulation, separation of
                concerns and to allow for easy expansion in the future.
"""
from mvc.controller import ReputationCheckerController


def main():
    """Initialize application flow."""
    application = ReputationCheckerController()
    application.run()


if __name__ == '__main__':
    main()