# NetSuite

A personal desktop workspace for your network, devices and local diagnostics.

The interface uses a navy palette, grouped sidebar navigation, a machine
header and a compact overview of saved devices, trusted hardware and available
tools. Daily monitoring, diagnostics and lab tools have separate navigation
groups. `Ctrl+1` opens the overview; `Ctrl+2` opens your devices.

## Setup

Python 3.10+ on a Linux desktop.
From this folder:

```sh
sudo apt install python3-venv python3-tk nmap network-manager iproute2
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python3 netsuite.py
```

`./run.sh` works from any directory and uses `.venv/bin/python` when present,
otherwise `python3` from your current environment. Install OS dependencies
separately. No launcher installs packages automatically.

## Desktop launcher

```sh
python3 install-launcher.py --desktop
```

Run the installer as your normal desktop user. It adds the app to your application
menu and desktop with its bundled icon. Omit `--desktop` for a menu entry only.
Keep the checkout in place; rerun the installer after moving it. On desktops that
ask, choose **Allow Launching** or **Mark as Trusted** for the desktop shortcut.

The icon requests administrator authentication through PolicyKit (`pkexec`).
Install your distribution's PolicyKit package and use an X11 desktop session.
For a standard user icon instead, add `--normal-user` when installing.
For administrator launch from a graphical terminal, use `./run-admin.sh`.
This preserves X11 display authentication and uses this project's virtual
environment. Elevated sessions store home-directory settings and exports as root;
desktop notifications may be unavailable. Native Wayland elevation is unsupported.

## Checks

```sh
python3 -m compileall -q -x '/\.venv/' .
# For GUI tests, install xvfb and xauth, then run:
xvfb-run -a python3 -m unittest discover -s tests -v
bash -n *.sh
```

The GitHub Actions workflow runs these offline checks on Python 3.10, 3.12 and
3.13 and 3.14. It checks GUI construction under a virtual X11 display, without live network
operations or administrator authentication. Hardware behavior needs local testing.

## Repository use

This folder is self-contained: copy it into its own GitHub repository with its
hidden `.github/` and `.gitignore` files. No sibling projects are required.
Generated data, credentials, captures and virtual environments are ignored.
No license has been selected; add your chosen LICENSE before distributing under
an open-source license.

## Network use

Use active testing features only on systems you own or are authorized to test.
Monitor mode requires a compatible adapter and root and can interrupt that
adapter. Discovery through nmcli requires NetworkManager.

The Overview lists optional tools for individual features. Diagnostics may
need `iputils-ping traceroute dnsutils whois iptables tcpdump`; security tabs
have additional prerequisites. Packet capture and firewall changes require
root. State stays in `~/.netsuite_*.json` and `~/netsuite.log`. Optional Scapy
failures disable capture without preventing other tabs from loading.

## Troubleshooting

- Missing Python module: install `requirements.txt` into `.venv` if provided.
- Missing `tkinter`: install the Python Tk package from your OS package manager.
- A command is unavailable: install the corresponding OS package listed above.
- Icons stopped working after moving the checkout: rerun `install-launcher.py`.
