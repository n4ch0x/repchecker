"""
Author:         Nacho Pobes
Student number: 500855533
Name:           RepChecker
Version:        1.0
"""


class InputError(Exception):
    """Base class for other exceptions."""
    pass


class IpIsUnknownTypeError(InputError):
    """Raised when an IP address fails to qualify as an IPv4 and IPv6 address.

        Args:
            InputError (object): the base class from which inherits
    """
    pass


class IpIsLoopbackError(InputError):
    """Raised when an IP address is a loopback address.

        Args:
            InputError (object): the base class from which inherits
    """
    pass


class IpIsMulticastError(InputError):
    """Raised when an IP address is a multicast address.

        Args:
            InputError (object): the base class from which inherits
    """
    pass


class IpIsLinkLocalError(InputError):
    """Raised when an IP address is reserved for link-local usage.

        Args:
            InputError (object): the base class from which inherits
    """
    pass


class IpIsReservedError(InputError):
    """Raised when an IP address is IETF reserved.

        Args:
            InputError (object): the base class from which inherits
    """
    pass


class IpIsUnspecifiedError(InputError):
    """Raised when an IP address is unspecified."""
    pass


class IpIsPrivateError(InputError):
    """Raised when an IP address is private."""
    pass