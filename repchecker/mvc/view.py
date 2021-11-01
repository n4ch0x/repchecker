"""
Author:         Nacho Pobes
Student number: 500855533
Name:           RepChecker
Version:        1.0
"""

from tkinter import *
from tkinter.font import Font
from pathlib import Path
import datetime


class ReputationCheckerView:
    """Present GUI and collected reputation data.

    Attributes:
        window (object): the window object which holds the GUI
        logo_image (object): an image object with the logo
        update_references (dict): a collection of placeholders to display the collected data
    """

    def __init__(self):
        """Create base window."""
        self.window = Tk()

        # Window dimensions
        window_width = 848
        window_height = 480
        self.window.geometry(f"{window_width}x{window_height}")
        self.window.minsize(window_width, window_height)
        self.window.maxsize(window_width, window_height)

        # Variable ``logo_image`` must be defined as an attribute to be able to persist and hold the image
        # until the moment of rendering
        self.logo_image = None

        # Placeholders for display
        self.update_references = {}

    def compose(self):
        """Create and assemble all the different components of the window."""
        # Top window bar
        self.window.iconbitmap(str(Path(__file__).parent.parent.absolute()) + str(Path("/images/hva_icon.ico")))
        self.window.title("HvA - RepChecker v1.0")

        # Outer frame
        main_frame = self._compose_main_frame()

        # Headers
        self._compose_header(main_frame)
        self._compose_subheader(main_frame)

        # Logo
        self._compose_logo(main_frame)

        # Input
        self._compose_input(main_frame)

        # General information
        self._compose_general_information(main_frame)

        # AbuseIPDB information
        self._compose_abuseipdb_information(main_frame)

        # VirusTotal information
        self._compose_virustotal_information(main_frame)

    def _compose_main_frame(self):
        """Compose outer frame."""
        main_frame = LabelFrame(self.window, padx=5, pady=5)
        main_frame.place(x=20, y=20, width=808, height=442)
        return main_frame

    def _compose_header(self, main_frame):
        """Compose main header.

        Args:
            main_frame (object): outer frame where to be added to
        """
        header_font = Font(family="Open Sans", size=22, weight="bold", slant="roman", underline=0, overstrike=0)
        header = Label(main_frame, text="RepChecker v1.0", font=header_font, anchor="w")
        header.place(x=15, y=10, width=450)

    def _compose_subheader(self, main_frame):
        """Compose subtitle.

        Args:
            main_frame (object): outer frame where to be added to
        """
        subheader_font = Font(family="Open Sans", size=12, weight="normal", slant="italic", underline=0, overstrike=0)
        subheader = Label(main_frame, text="FQDN & IP address reputation checker", font=subheader_font, anchor="w")
        subheader.place(x=15, y=45, width=450)

    def _compose_logo(self, main_frame):
        """Compose logo image.

        Args:
            main_frame (object): outer frame where to be added to
        """
        self.logo_image = PhotoImage(file=str(Path(__file__).parent.parent.absolute()) + str(Path("/images/hva_logo_en.png")))
        logo = Label(main_frame, image=self.logo_image)
        logo.place(x=435, y=20, width=350, height=46)

    def _compose_input(self, main_frame):
        """Compose input section.

        Args:
            main_frame (object): outer frame where to be added to
        """
        # Input label
        label_font = Font(family="Open Sans", size=10, weight="normal", slant="roman", underline=0, overstrike=0)
        input_label = Label(main_frame, text="Please enter a FQDN or an IP address (v4 or v6):", font=label_font, anchor="w")
        input_label.place(x=15, y=100, width=500)
        self.update_references["input_label"] = input_label     # reference to be able to update the value

        # Input field
        input_font = Font(family="Open Sans", size=11, weight="normal", slant="roman", underline=0, overstrike=0)
        input_field = Entry(main_frame, borderwidth=1, relief="solid", font=input_font)
        input_field.place(x=15, y=120, width=439, height=24)
        self.update_references["input_field"] = input_field     # reference to be able to read and update the value

        # Submit button
        button_font = Font(family="Open Sans", size=11, weight="normal", slant="roman", underline=0, overstrike=0)
        submit_button = Button(main_frame, text="Check", font=button_font, borderwidth=1, relief="solid")
        submit_button.place(x=459, y=120, width=50, height=24)
        self.update_references["submit_button"] = submit_button     # reference to be able to configure behavior

    def _compose_general_information(self, main_frame):
        """Compose general information section.

        Args:
            main_frame (object): outer frame where to be added to
        """
        # Frame
        info_frame = LabelFrame(main_frame, text="  General information  ", padx=5, pady=5)
        info_frame.place(x=15, y=160, width=440, height=255)

        info_font = Font(family="Open Sans", size=10, weight="normal", slant="roman", underline=0, overstrike=0)

        # FQDN
        fqdn_label = Label(info_frame, text="FQDN:", font=info_font, anchor="w")
        fqdn_label.place(x=5, y=10, width=200)
        fqdn_value_label = Label(info_frame, font=info_font, anchor="w")
        fqdn_value_label.place(x=215, y=10, width=200)
        self.update_references["fqdn_value"] = fqdn_value_label     # reference to be able to update the value

        # IP address
        ip_label = Label(info_frame, text="IP address:", font=info_font, anchor="w")
        ip_label.place(x=5, y=30, width=200)
        ip_value_label = Label(info_frame, font=info_font, anchor="w")
        ip_value_label.place(x=215, y=30, width=200)
        self.update_references["ip_address_value"] = ip_value_label     # reference to be able to update the value

        # Network
        network_label = Label(info_frame, text="Network:", font=info_font, anchor="w")
        network_label.place(x=5, y=50, width=200)
        network_value_label = Label(info_frame, font=info_font, anchor="w")
        network_value_label.place(x=215, y=50, width=200)
        self.update_references["network_value"] = network_value_label     # reference to be able to update the value

        # ISP
        isp_label = Label(info_frame, text="ISP:", font=info_font, anchor="w")
        isp_label.place(x=5, y=70, width=200)
        isp_value_label = Label(info_frame, font=info_font, anchor="w")
        isp_value_label.place(x=215, y=70, width=200)
        self.update_references["isp_value"] = isp_value_label     # reference to be able to update the value

        # Country
        country_label = Label(info_frame, text="Country:", font=info_font, anchor="w")
        country_label.place(x=5, y=90, width=200)
        country_value_label = Label(info_frame, font=info_font, anchor="w")
        country_value_label.place(x=215, y=90, width=200)
        self.update_references["country_value"] = country_value_label     # reference to be able to update the value

        # Continent
        continent_label = Label(info_frame, text="Continent:", font=info_font, anchor="w")
        continent_label.place(x=5, y=110, width=200)
        continent_value_label = Label(info_frame, font=info_font, anchor="w")
        continent_value_label.place(x=215, y=110, width=200)
        self.update_references["continent_value"] = continent_value_label     # reference to be able to update the value

        # Registry
        registry_label = Label(info_frame, text="Regional Internet Registry:", font=info_font, anchor="w")
        registry_label.place(x=5, y=130, width=200)
        registry_value_label = Label(info_frame, font=info_font, anchor="w")
        registry_value_label.place(x=215, y=130, width=200)
        self.update_references["registry_value"] = registry_value_label     # reference to be able to update the value

    def _compose_abuseipdb_information(self, main_frame):
        """Compose AbuseIPDB section.

        Args:
            main_frame (object): outer frame where to be added to
        """
        # Frame
        abuseipdb_frame = LabelFrame(main_frame, text="  AbuseIPDB reputation  ", padx=5, pady=5)
        abuseipdb_frame.place(x=460, y=160, width=320, height=110)

        info_font = Font(family="Open Sans", size=10, weight="normal", slant="roman", underline=0, overstrike=0)
        info_font_bold = Font(family="Open Sans", size=10, weight="bold", slant="roman", underline=0, overstrike=0)

        # Abuse information
        abuse_label = Label(abuseipdb_frame, font=info_font_bold, fg="#fff")
        abuse_label.place(x=5, y=10, width=293, height=30)
        self.update_references["abuse_value"] = abuse_label     # reference to be able to update the value

        # Total reports
        total_label = Label(abuseipdb_frame, font=info_font, anchor="w")
        total_label.place(x=5, y=40, width=293)
        self.update_references["abuse_users_value"] = total_label     # reference to be able to update the value

        # Date reports
        date_abuse_label = Label(abuseipdb_frame, font=info_font, anchor="w")
        date_abuse_label.place(x=5, y=60, width=293)
        self.update_references["abuse_date_value"] = date_abuse_label     # reference to be able to update the value

    def _compose_virustotal_information(self, main_frame):
        """Compose VirusTotal section.

        Args:
            main_frame (object): outer frame where to be added to
        """
        # Frame
        virustotal_frame = LabelFrame(main_frame, text="  VirusTotal reputation  ", padx=5, pady=5)
        virustotal_frame.place(x=460, y=280, width=320, height=135)

        info_font = Font(family="Open Sans", size=10, weight="normal", slant="roman", underline=0, overstrike=0)
        info_font_bold = Font(family="Open Sans", size=10, weight="bold", slant="roman", underline=0, overstrike=0)

        # Malicious information
        malicious_label = Label(virustotal_frame, font=info_font_bold, fg="#fff")
        malicious_label.place(x=5, y=10, width=90, height=70)
        self.update_references["malicious_value"] = malicious_label     # reference to be able to update the value

        # Suspicious information
        suspicious_label = Label(virustotal_frame, font=info_font_bold, fg="#fff")
        suspicious_label.place(x=107, y=10, width=90, height=70)
        self.update_references["suspicious_value"] = suspicious_label     # reference to be able to update the value

        # Harmless information
        harmless_label = Label(virustotal_frame, font=info_font_bold, fg="#fff")
        harmless_label.place(x=209, y=10, width=90, height=70)
        self.update_references["harmless_value"] = harmless_label     # reference to be able to update the value

        # Date reports
        date_virus_label = Label(virustotal_frame, font=info_font, anchor="w")
        date_virus_label.place(x=5, y=85, width=293)
        self.update_references["date_virus_value"] = date_virus_label     # reference to be able to update the value

    def activate(self, event):
        """Activate window in order to be able to accept input.

        Args:
            event (object): controller method to be called upon submitting input
        """
        self.update_references["input_field"].focus()
        self.update_references["input_field"].bind('<Return>', event)
        self.update_references["submit_button"].configure(command=event)

    def display(self):
        """Make window visible."""
        self.window.mainloop()

    def get_input_value(self):
        """ Retrieve value input field.

        Returns:
            input_value (str): the filled in value
        """
        return self.update_references["input_field"].get().strip()  # remove any leading and trailing whitespaces

    def _display_error(self, error_message):
        """Display error message.

        Args:
            error_message (str): the error message to be displayed
        """
        self.update_references["input_label"].configure(text=error_message, fg="#e74c3c")

    def reset_error(self):
        """Set back normal label text."""
        self.update_references["input_label"].configure(text="Please enter a FQDN or an IP address (v4 or v6):", fg="#000000")

    def display_fqdn_validation_error(self):
        """Display FQDN validation error message."""
        self._display_error("There has been a problem validating the FQDN. Please try again.")

    def display_converting_fqdn_error(self):
        """Display FQDN conversion error message."""
        self._display_error("There has been a problem converting the FQDN to an IP address. Please try again.")

    def display_ip_validation_error(self):
        """Display IP address validation error message."""
        self._display_error("The given IP address is not valid. Please try again.")

    def display_invalid_ip_error(self):
        """Display incorrect IP address error message."""
        self._display_error("The given IP address cannot be used. Please try again.")

    def display_is_loopback_error(self):
        """Display loopback IP address error message."""
        self._display_error("This address seems to be a loopback address. Please try again.")

    def display_is_multicast_error(self):
        """Display multicast IP address error message."""
        self._display_error("This address seems to be a multicast address. Please try again.")

    def display_is_link_local_error(self):
        """Display link-local IP address error message."""
        self._display_error("This address seems to be reserved for link-local usage. Please try again.")

    def display_is_reserved_error(self):
        """Display IETF reserved IP address error message."""
        self._display_error("This address seems to be IETF reserved. Please try again.")

    def display_is_unspecified_error(self):
        """Display unspecified IP address error message."""
        self._display_error("This address seems to be unspecified. Please try again.")

    def display_is_private_error(self):
        """Display private IP address error message."""
        self._display_error("This address seems to be private. Please try again.")

    def display_invalid_fqdn_ip_error(self):
        """Display invalid FQDN and/or IP address error message."""
        self._display_error("The given FQDN or IP address is not valid. Please try again.")

    def display_http_error(self, error_code):
        """Display HTTP error message.

        Args:
            error_code (str): the HTTP code given by the server
        """
        self._display_error(f"The server couldn't fulfill the request (HTTP {error_code}). Please try again.")

    def display_url_error(self, error_reason):
        """Display URL error message.

        Args:
            error_reason (str): the reason of the failure
        """
        self._display_error(f"The server couldn't be reached (reason: {error_reason}). Please try again.")

    def show_reputation_data(self, ip_address, fqdn=None, reputation_data={}):
        """Display the collected reputation data.

        Args:
            ip_address (str): the used IP address
            fqdn (str): the used FQDN, if present
            reputation_data (dict): the data to be displayed
        """
        self.update_references["ip_address_value"].configure(text=ip_address)
        self.update_references["fqdn_value"].configure(text=fqdn or "N/A")
        self.update_references["network_value"].configure(text=reputation_data["general_information"]["network"] or "N/A")
        self.update_references["isp_value"].configure(text=reputation_data["general_information"]["isp"] or "N/A")
        self.update_references["country_value"].configure(text=reputation_data["general_information"]["country"] or "N/A")
        self.update_references["continent_value"].configure(text=reputation_data["general_information"]["continent"] or "N/A")
        self.update_references["registry_value"].configure(text=reputation_data["general_information"]["registry"] or "N/A")

        confidence_rate = reputation_data["abuseipdb"]["abuse_confidence"]
        if (confidence_rate == 0):
            confidence_color = "#27ae60"
        elif (confidence_rate < 75):
            confidence_color = "#ffc300"
        else:
            confidence_color = "#e74c3c"
        self.update_references["abuse_value"].configure(bg=confidence_color)
        self.update_references["abuse_value"].configure(text=f"Abuse confidence {confidence_rate}%")

        total_abuse_reports = reputation_data["abuseipdb"]["total_reports"]
        total_abuse_reporters = reputation_data["abuseipdb"]["total_users"]
        if (total_abuse_reports > 0):
            time_string = "time" if total_abuse_reports == 1 else "times"
            user_string = "user" if total_abuse_reports == 1 else "users"
            report_text = f"Address reported {total_abuse_reports} {time_string} by {total_abuse_reporters} {user_string}"
            date = datetime.datetime.strptime(reputation_data["abuseipdb"]["report_date"], "%Y-%m-%dT%H:%M:%S%z").date()
            date_text = f"Last report on {date.strftime('%d %B %Y')}"
            self.update_references["abuse_users_value"].configure(text=report_text)
            self.update_references["abuse_date_value"].configure(text=date_text)
        else:
            report_text = "This address has not (yet) been reported"
            self.update_references["abuse_users_value"].configure(text=report_text)

        total_malicious_stats = reputation_data["virustotal"]["malicious_stats"]
        total_suspicious_stats = reputation_data["virustotal"]["suspicious_stats"]
        total_harmless_stats = reputation_data["virustotal"]["harmless_stats"]
        self.update_references["malicious_value"].configure(bg="#e74c3c")
        self.update_references["malicious_value"].configure(text=f"{total_malicious_stats}\nmalicious")
        self.update_references["suspicious_value"].configure(bg="#ffc300")
        self.update_references["suspicious_value"].configure(text=f"{total_suspicious_stats}\nsuspicious")
        self.update_references["harmless_value"].configure(bg="#27ae60")
        self.update_references["harmless_value"].configure(text=f"{total_harmless_stats}\nharmless")
        date = datetime.datetime.fromtimestamp(reputation_data["virustotal"]["report_date"])
        date_text = f"Last report on {date.strftime('%d %B %Y')}"
        self.update_references["date_virus_value"].configure(text=date_text)

    def reset_reputation_data(self):
        """Resets all the values of previous collected reputation data to empty values."""
        self.update_references["ip_address_value"].configure(text="")
        self.update_references["fqdn_value"].configure(text="")
        self.update_references["network_value"].configure(text="")
        self.update_references["isp_value"].configure(text="")
        self.update_references["country_value"].configure(text="")
        self.update_references["continent_value"].configure(text="")
        self.update_references["registry_value"].configure(text="")

        self.update_references["abuse_value"].configure(bg="SystemButtonFace")
        self.update_references["abuse_value"].configure(text="")
        self.update_references["abuse_users_value"].configure(text="")
        self.update_references["abuse_date_value"].configure(text="")
        self.update_references["malicious_value"].configure(bg="SystemButtonFace")
        self.update_references["malicious_value"].configure(text="")
        self.update_references["suspicious_value"].configure(bg="SystemButtonFace")
        self.update_references["suspicious_value"].configure(text="")
        self.update_references["harmless_value"].configure(bg="SystemButtonFace")
        self.update_references["harmless_value"].configure(text="")
        self.update_references["date_virus_value"].configure(text="")