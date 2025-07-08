#!/usr/bin/env python3

"""
This program parses JSON output from lldpctl and looks for an
interface that has the propper tagged vlan on an interface 
"""

import argparse
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from typing import List
from importlib.machinery import FileFinder, SourceFileLoader, SOURCE_SUFFIXES


class ECBPSvcExc(Exception):
    """ Base exception """

class ECBPFServiceHandler: # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """ Simple context, mainly for tracking testing data """

    DEFAULT_CONF = "/etc/ecbpf/service.conf"

    def __init__(self):

        # Test flags
        self._dry_run = False # Don't exec commands
        self._skip_vlan_check = False # Don't do a vlan sanity check

        # Ingress (vlan 13) and egress (vlan 10)
        self._ingress_bond_num = 0
        self._egress_bond_num = 1
        self._ingress_vlan = 100
        self._egress_vlan = 200

        # XDP Filter Options
        self._xdp_filter_frags_drop = False
        self._xdp_filter_ptb_max_pps = 0 # Don't send PTB

        # Test data
        self._bond_test_data = {}

    @property
    def dry_run(self) -> bool:
        """ Don't exec commands """

        return self._dry_run

    @dry_run.setter
    def dry_run(self, dry_run: bool) -> None:
        """ True for dry run mode """

        self._dry_run = bool(dry_run)
        logging.info("Dry run mode: %s", self._dry_run)

    @property
    def bond_test_data(self) -> dict:
        """ Use test data instead of getting bond info from proc """

        return self._bond_test_data

    @bond_test_data.setter
    def bond_test_data(self, bond_data: dict) -> None:
        """ Use test data instead of getting bond info from proc.  Dict
        index is bond num int """

        self._bond_test_data = bond_data

    @property
    def ingress_vlan(self) -> int:
        """ Ingress VLAN (usually 13) """

        return self._ingress_vlan

    @ingress_vlan.setter
    def ingress_vlan(self, vlan: int) -> None:
        """ Ingress VLAN is an int """

        self._ingress_vlan = self._validate_vlan(vlan) # raises on error

    @property
    def egress_vlan(self) -> int:
        """ Egress VLAN (usually 13) """

        return self._egress_vlan

    @egress_vlan.setter
    def egress_vlan(self, vlan: int) -> None:
        """ Egress VLAN is an int """

        self._egress_vlan = self._validate_vlan(vlan) # raises on error

    @property
    def skip_vlan_check(self) -> bool:
        """ Skip vlan sanity check for pops that don't support them """

        return self._skip_vlan_check

    @property
    def xdp_filter_frags_drop(self) -> bool:
        """ xdp filter configuration: enable dropping IPv4 fragments """

        return self._xdp_filter_frags_drop

    @property
    def xdp_filter_ptb_max_pps(self) -> int:
        """ xdp filter configuration: Rate limit for responding with
        PTB to dropped frags. 0 for off """

        if self._xdp_filter_ptb_max_pps < 0:
            return 0

        return self._xdp_filter_ptb_max_pps

    def _has_tagged_egress(self) -> bool:
        """ Check for a vlan interface on the ingress bond interface and
        return True/False. """

        fname = f"/sys/class/net/bond{self._ingress_bond_num}.{self._egress_vlan}"

        return os.path.exists(fname)

    @property
    def ingress_bond(self) -> str:
        """ Return name of ingress bond """

        return f"bond{self._ingress_bond_num}"

    @property
    def egress_bond(self) -> str:
        """ Return name of egress bond """

        if self._has_tagged_egress():
            return f"bond{self._ingress_bond_num}.{self._egress_vlan}"

        return f"bond{self._egress_bond_num}"

    @property
    def ingress_interfaces(self) -> List[str]:
        """ Return list of ingress interfaces associated with the ingress bond """

        ifnames = self.get_bond_ifnames(self._ingress_bond_num)

        if not ifnames:
            raise ECBPSvcExc(f"No interfaces found for bond{self._ingress_bond_num}")

        return ifnames

    @property
    def egress_interfaces(self) -> List[str]:
        """ Return a list of egress interfaces """

        if self._has_tagged_egress():
            return self.ingress_interfaces

        ifnames = self.get_bond_ifnames(self._egress_bond_num)

        if not ifnames:
            raise ECBPSvcExc(f"No interfaces found for bond{self._egress_bond_num}")

        return ifnames

    @staticmethod
    def _validate_vlan(vlan: int) -> int:
        """ Validate VLAN for ingress and egress """

        try:
            vlan = int(vlan)
        except ValueError:
            logging.exception("VLAN must be an integer, not %s", vlan)
            raise

        if not 0 < vlan < 4095: # VID of 0x000 and 0xFFF are reserved.
            message = f"VLAN out of range: {vlan}"
            logging.error(message)
            raise ValueError(message)

        return vlan

    def load_default_config(self) -> None:
        """ Load the default config """

        if os.path.isfile(self.DEFAULT_CONF):
            self.load_config(self.DEFAULT_CONF)

    def load_config(self, filename: str) -> None:
        """ Load a configuration file """

        with open(filename, encoding="utf-8") as conff:
            conf = json.load(conff)

        if "egress_vlan" in conf:
            self.egress_vlan = conf["egress_vlan"]

        if "ingress_vlan" in conf:
            self.ingress_vlan = conf["ingress_vlan"]

        if "skip_vlan_check" in conf:
            self._skip_vlan_check = bool(conf["skip_vlan_check"])

        # XDP Filter toggles
        if "xdp_filter_frags_drop" in conf:
            self._xdp_filter_frags_drop = bool(conf["xdp_filter_frags_drop"])

        if "xdp_filter_ptb_max_pps" in conf:
            self._xdp_filter_ptb_max_pps = int(conf["xdp_filter_ptb_max_pps"])

    @staticmethod
    def get_lldpd_interfaces() -> list:
        """ Call lldpctl and return a dictionary of data """

        command = "lldpctl -f json"

        try:
            output = subprocess.check_output(shlex.split(command))
        except subprocess.CalledProcessError as exc:
            logging.error("lldpctl exited with status %s", exc.returncode)
            logging.error("stdout was:\n---\n%s\n---", exc.stdout)
            logging.error("stderr was:\n---\n%s\n---", exc.stderr)
            raise
        except FileNotFoundError:
            logging.error("lldpctl not found or installed")
            raise

        try:
            lldpd = json.loads(output.decode())
            logging.debug("Result from lldpctl: %s", lldpd)
        except Exception: # pylint: disable=broad-except
            logging.exception("Failed to decode output from lldpctl")
            raise

        # Strip out the upper levels
        lldpd = lldpd.get('lldp', {})
        lldpd = lldpd.get('interface', [])

        # If there is only one interface at the time, there is no array...
        # https://github.com/lldpd/lldpd/blob/0.9.9/src/client/json_writer.c#L223-L224
        if isinstance(lldpd, dict):
            return [lldpd]

        return lldpd

    def get_lldp_interface(self, ifname: str) -> dict:
        """ Return lldp information for the supplied ifname """

        interfaces = self.get_lldpd_interfaces()

        for interface in interfaces:
            if ifname in interface.keys(): # Make sure it is a list(dict)
                return interface[ifname]

        logging.warning("Interface %s not found in %s", ifname, interfaces)
        return {}

    def validate_vlans(self, ifname: str, retry_time: int = 30, retries: int = 10):
        """ Lookup an interface and see if it has the right vlan setup. Raise
            ECBPSvcExc on a problem.  """

        if self.skip_vlan_check:
            logging.info("Skipping VLAN validation for interface %s due do configuration", ifname)
            return

        # It is possible to get an empty list back if lldpd was recently started:
        #
        # # lldpctl -f json
        # {
        #   "lldp": {
        #
        #   }
        # }
        #
        interface = self.get_lldp_interface(ifname)

        for _ in range(retries):
            if interface: # Avoid indenting this whole block
                break

            logging.warning("LLDP information for interface %s not found.  Retrying in %s seconds.",
                            ifname, retry_time)
            time.sleep(retry_time)

            interface = self.get_lldp_interface(ifname)

        if not interface:
            message = f"No LLDP information for {ifname}"
            raise ECBPSvcExc(message)

        vlans = interface.get('vlan', [])
        logging.debug("VLANS for %s: %s", ifname, vlans)

        # UGH! vlans can be either a list or a single dict...
        if not isinstance(vlans, list):
            message = f"Interface {ifname} has only one VLAN"
            raise ECBPSvcExc(message)

        has_untagged_ingress = False 
        has_tagged_egress = False 

        for vlan in vlans:
            try:
                # lldpctl returns ints as str :-(
                vid = int(vlan.get("vlan-id", -1))
            except ValueError as exc:
                message = ("Unexpected non-int value for key vlan-id from "
                           "lldpctl, json may have changed.")
                raise ECBPSvcExc(message) from exc

            if vid == self.egress_vlan:
                if not vlan.get("pvid", False):
                    logging.debug("Interface %s has tagged egress VLAN %s",
                                  ifname, self.egress_vlan)
                    has_tagged_egress = True

            elif vid == self.ingress_vlan:
                if vlan.get("pvid", False):
                    logging.debug("Interface %s has untagged ingress VLAN %s",
                                  ifname, self.ingress_vlan)
                    has_untagged_ingress = True

        if not (has_tagged_egress and has_untagged_ingress):
            message = (f"Interface {ifname} does not have an untagged VLAN {self.ingress_vlan}"
                       f" and tagged {self.egress_vlan}")
            raise ECBPSvcExc(message)

        logging.debug("Interface %s matches criteria", ifname)

    def get_bond_ifnames(self, bond_num: int) -> list:
        """ Return a list of interfaces that comprised bond# """

        bond_file = f"/proc/net/bonding/bond{bond_num}"

        if self.bond_test_data:
            bond = self.bond_test_data[bond_num].split("\n")
        else:
            with open(bond_file, encoding="utf-8") as bond_fh:
                bond = bond_fh.readlines()

        interfaces = []

        pattern = re.compile(r"^Slave Interface:\s+([a-z]+[0-9]+)")
        for line in bond:
            match = pattern.match(line)

            if match:
                interfaces.append(match.group(1))

        if not interfaces:
            message = f"Failed to parse interfaces for bond{bond_num}."
            raise ECBPSvcExc(message)

        return interfaces

    def xdp_root(self, start: bool = False, skip_nop: bool = False):
        """ Handle running XDP Root Array """

        if start:
            command = ('/usr/bin/xdp_root_loader --debug --attach '
                       f'--interface {",".join(self.ingress_interfaces)}')
        else:
            command = ('/usr/bin/xdp_root_loader --debug --detach --nop '
                      f'--interface {",".join(self.ingress_interfaces)}')

            if not skip_nop:
                command += " --nop"


        logging.info("Running: %s", command)

        if self.dry_run: # Short circuit in test mode
            return

        cmdv = shlex.split(command)
        os.execvp(cmdv[0], cmdv)

    def xdp_sampler(self, start: bool = False):
        """ Handle running XDP Sampler """

        if not start:
            message = "Stop not supported.  Process does not exit, use systemctl."
            raise ECBPSvcExc(message)

        command = ('/usr/bin/xdp_sampler --port 12354 '
                   f'--interface {",".join(self.ingress_interfaces)} --statsd')

        logging.info("Running: %s", command)

        if self.dry_run: # Short circuit in test mode
            return

        cmdv = shlex.split(command)
        os.execvp(cmdv[0], cmdv)

    def xdp_filter(self, start: bool = False):
        """ Handle running XDP filter """

        if start:
            command = ('/usr/bin/xdp_filter --attach --statsd --statsd-detach-on-exit '
                       f'--interface {",".join(self.ingress_interfaces)}')

            if self.xdp_filter_frags_drop:
                command += (f' --frags-drop --ptb-max-pps {self.xdp_filter_ptb_max_pps}')
            else:
                command += (' --no-frags-drop')

        else:
            # This isn't used by systemd since we start and go into a loop
            # with --statsd and use --statsd-detach-on-exit to clean up,
            # but this may be useful is things get mucked up.
            command = ('/usr/bin/xdp_filter --detach '
                       f'--interface {",".join(self.ingress_interfaces)}')

        logging.info("Running: %s", command)

        if self.dry_run: # Short circuit in test mode
            return

        cmdv = shlex.split(command)
        os.execvp(cmdv[0], cmdv)

    def xdp_bypass_ipvs(self, start: bool = False):
        """ Handle running XDP Bypass """

        # Handle skipping vips for directors that are also dnsa
        excluded_vips = ""
        if 'dnsa' in _getsrvinfo('subpurposes'):
            ecdns_anycast_vips = _getsrvinfo("ecdns-anycast-vips").split()

            if ecdns_anycast_vips:
                excluded_vips = f'-e add {",".join(ecdns_anycast_vips)}'


        ifin = ",".join(self.ingress_interfaces)
        if self._has_tagged_egress():
            ifout = self.egress_bond
            additional_if = self.ingress_bond
        else:
            # Double check that we have the right vlans
            for ifname in self.ingress_interfaces:
                self.validate_vlans(ifname)

            ifout = ",".join(self.egress_interfaces)
            additional_if = f"{self.ingress_bond},{self.egress_bond}"

        if start:
            command = ("/usr/bin/taskset 0x00005555 /usr/bin/xdp_bypass_ipvs"
                       f" -v {self.egress_vlan} -L -i {ifin} -o {ifout}"
                       f" -a {additional_if} {excluded_vips}"
                      )
        else:
            command = ("/usr/bin/xdp_bypass_ipvs -U -F"
                       f" -i {ifin} -o {ifout}")

        logging.info("Running: %s", command)

        if self.dry_run: # Short circuit in test mode
            return

        cmdv = shlex.split(command)
        os.execvp(cmdv[0], cmdv)

    def xdp_check(self):
        """ Run a check to make sure the networking is sane """

        # If we have tagged egress, we can skip the vlan check
        if self._has_tagged_egress():
            return

        for ifname in self.ingress_interfaces:
            self.validate_vlans(ifname)

def main() -> int:
    """ main main """

    # defaults
    log_level = logging.INFO
    start = False
    skip_nop = False

    # args
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Print debug level output")
    parser.add_argument("-r", "--dry-run", action="store_true",
                        help="Use internal test data instead of lldpctl")
    parser.add_argument("-c", "--config", type=str, default="",
                        help="Service configuration file")
    parser.add_argument("-s", "--skip-nop", action="store_true",
                        help=("Perform full detach of root array instead of "
                              "replacing it with a dummy NOP program."))
    parser.add_argument("start_stop", choices=["start", "stop"])
    parser.add_argument("unit", choices=["root", "sampler", "bypass", "filter", "check"])
    args = parser.parse_args()

    # Logging
    if args.debug:
        log_level = logging.DEBUG

    logging.basicConfig(level=log_level)

    ret = 0
    try:
        # Setup ctx
        ctx = ECBPFServiceHandler()

        if args.config:
            ctx.load_config(args.config)
        else:
            ctx.load_default_config()

        if args.dry_run:
            ctx.dry_run = True

        if args.start_stop == "start":
            start = True

        if args.skip_nop:
            skip_nop = True

        # Services
        if args.unit == "root":
            ctx.xdp_root(start, skip_nop)
        elif args.unit == "sampler":
            ctx.xdp_sampler(start)
        elif args.unit == "bypass":
            ctx.xdp_bypass_ipvs(start)
        elif args.unit == "filter":
            ctx.xdp_filter(start)
        elif args.unit == "check":
            ctx.xdp_check()
    except Exception: # pylint: disable=broad-except
        logging.exception("Unhandled exception: failed to start %s", args.unit)
        ret = 2

    return ret

if __name__ == "__main__":
    sys.exit(main())
