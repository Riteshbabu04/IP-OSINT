
# IP-OSINT

A simple command-line tool to gather Open Source Intelligence (OSINT) on a given IP address by providing links and descriptions of various online analysis tools, with flexible options for category selection and browser opening.

## Usage

You can provide the IP address and choose categories either as command-line arguments or through an interactive menu.

**1. Clone the repository:**
```bash
git clone https://github.com/Rajnayak0/IP-OSINT.git
cd IP-OSINT
```

**2. Install dependencies:**
```bash
pip install pyfiglet termcolor
```

**3: Enter IP and select categories interactively:**
```bash
python ip.py
```
The script will prompt you for the IP address and then present a menu of categories.

**4. Interactive Category Selection:**

If you run the script without category flags, you will see an interactive menu:

* `[0] All Categories`
* `[1] Geolocation`
* `[2] Host / Port Discovery`
* `[3] IPv4 Specific`
* `[4] Reputation / Blacklists`
* `[5] Neighbor Domains (Reverse IP Lookup)`
* `[b] Go Back`
* `[q] Quit`

Enter the number corresponding to your desired category.

**5. Open Links in Browser (Interactive Mode):**

After selecting a category in the interactive mode, you will be asked if you want to open the links in your browser.

**6. Confirmation and Navigation (Interactive Mode):**

The interactive mode allows you to explore multiple categories before quitting.

## With flags

**1. Run the script:**

**Option 1: Provide IP and categories via flags:**
```bash
python ip.py <IP_ADDRESS> [flags]
```
Replace `<IP_ADDRESS>` with the IP you want to investigate (e.g., `python ip.py 8.8.8.8`). Use the category flags below to select specific tools.


**2. Category Selection Flags:**

You can use these flags to select specific categories directly from the command line:

* `-o` or `--open`: Automatically open the links in your default web browser tabs.
* `-g` or `--geolocation`: Show tools from the Geolocation category.
* `-hp` or `--host_port`: Show tools from the Host / Port Discovery category.
* `-i4` or `--ipv4`: Show tools from the IPv4 Specific category.
* `-r` or `--reputation`: Show tools from the Reputation / Blacklists category.
* `-n` or `--neighbor`: Show tools from the Neighbor Domains (Reverse IP Lookup) category.
* `-a` or `--all`: Show tools from all categories.

**Example Usage with Flags:**
```bash
python ip.py 1.1.1.1 -g -r -o
```
This command will analyze the IP `1.1.1.1`, display tools from the Geolocation and Reputation/Blacklists categories, and open the links in your browser.





## Supported Operating Systems

This tool is written in Python and should be compatible with any operating system that supports Python 3. This includes:

* **Windows:** Versions 7, 8, 8.1, 10, 11
* **macOS:** All recent versions (e.g., Catalina, Big Sur, Monterey, Ventura, Sonoma)
* **Linux:** Various distributions (Ubuntu, Debian, Fedora, CentOS, Arch Linux, and more)

## Dependencies

* **Python 3:** Download from [https://www.python.org/downloads/](https://www.python.org/downloads/).
* **pyfiglet:** Install with `pip install pyfiglet`.
* **termcolor:** Install with `pip install termcolor`.

## Tools Included

* **Geolocation:** iplocation.net, ipinfo.io, MaxMind, ip2location.com, whatismyipaddress.com, db-ip.com, freegeoip.app
* **Host / Port Discovery:** viewdns.info, securitytrails.com, shodan.io, censys.io, zoomeye.org (and a note about online port scanners)
* **IPv4 Specific:** bgp.he.net, whois.arin.net, ipapi.co, ultratools.com
* **Reputation / Blacklists:** virustotal.com, abuseipdb.com, talosintelligence.com, mxtoolbox.com, spur.us, greynoise.io
* **Neighbor Domains (Reverse IP Lookup):** viewdns.info, completedns.com, securitytrails.com

Each tool includes a brief description and a "Potential Result" hint.


