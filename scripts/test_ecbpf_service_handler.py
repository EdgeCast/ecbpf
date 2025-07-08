#!/usr/bin/env python3

# pylint: disable=protected-access

import unittest
import copy
from unittest.mock import MagicMock, patch, mock_open

from ecbpf_service_handler import *
from test_ecbpf_service_handler_data import *
from test_ecbpf_service_handler_data_internal import *

class TestHandler(unittest.TestCase):

    def setUp(self):
        """ Called before each test """

        self.ctx_dry = ECBPFServiceHandler()
        self.ctx_dry.dry_run = True
        self.ctx_dry.load_config("test.conf")

    def test_vlan_validation(self):
        """ Test having bad VLAN values """

        ctx = ECBPFServiceHandler()

        with self.assertRaises(ValueError):
            ctx._validate_vlan("asdf123")

        with self.assertRaises(ValueError):
            ctx._validate_vlan(-1)

        with self.assertRaises(ValueError):
            ctx._validate_vlan(0)

        with self.assertRaises(ValueError):
            ctx._validate_vlan(0xfff)

        self.assertEqual(ctx._validate_vlan(1), 1)
        self.assertEqual(ctx._validate_vlan(4094), 4094)
        self.assertIsInstance(ctx._validate_vlan(23), int)

    @patch("subprocess.check_output")
    def test_vlan_validation_lldp(self, check_output):
        """ Test the parsing of lldpctl output to validate interface membership """

        ctx = self.ctx_dry

        data = json.loads(SINGLE_NIC_LLDP.decode())
        ifobj = data["lldp"]["interface"][0]
        ifname = list(ifobj.keys())[0]

        ctx.bond_test_data = SINGLE_NIC_BOND

        # Test non-list vlan
        ifobj[ifname]['vlan'] = 123
        check_output.return_value = str.encode(json.dumps({'lldp': { 'interface': [ifobj] }}))
        with self.assertRaisesRegex(ECBPSvcExc, r"has only one"):
            ctx.validate_vlans(ifname)

        # Test non-intable vid
        ifobj[ifname]['vlan'] = [{"vlan-id": "mooo"}]
        check_output.return_value = str.encode(json.dumps({'lldp': { 'interface': [ifobj] }}))
        with self.assertRaisesRegex(ECBPSvcExc, r"non-int"):
            ctx.validate_vlans(ifname)

    @patch("subprocess.check_output")
    def test_vlan_validation_lldp_vid(self, check_output):
        """ Make sure we fail on mismatched vlan ids """

        ctx = self.ctx_dry
        ctx.bond_test_data = SINGLE_NIC_BOND
        check_output.return_value = SINGLE_NIC_LLDP

        ctx.ingress_vlan = 123
        ctx.egress_vlan = 456

        with self.assertRaisesRegex(ECBPSvcExc, r"does not have"):
            ctx.validate_vlans("eth0")

    @patch("subprocess.check_output")
    def test_single_nic(self, check_output):
        """ Make sure we pick out a single nic """

        ctx = self.ctx_dry

        ctx.bond_test_data = SINGLE_NIC_BOND
        check_output.return_value = SINGLE_NIC_LLDP

        ifnames = ctx.ingress_interfaces
        self.assertEqual(["eth0"], ifnames)

    @patch("subprocess.check_output")
    def test_lldp_single_nic(self, check_output):
        """ Make sure we account for lldpd returning an dict instead of an array.  This is
        a anti-feature of lldpctl's encoder.
        https://github.com/lldpd/lldpd/blob/0.9.9/src/client/json_writer.c#L223-L224
        """

        ctx = self.ctx_dry

        ctx.bond_test_data = SINGLE_NIC_BOND
        check_output.return_value = ONLY_ONE_IF_LLDP

        interfaces = ctx.get_lldpd_interfaces()
        self.assertIsInstance(interfaces, list)

    @patch("subprocess.check_output")
    def test_dual_nic(self, check_output):
        """ Make sure we pick two nics """

        ctx = self.ctx_dry

        ctx.bond_test_data = DUAL_NIC_BOND
        check_output.return_value = DUAL_NIC_LLDP

        ifnames = ctx.ingress_interfaces
        self.assertEqual(["eth0", "eth2"], sorted(ifnames))

    @patch("subprocess.check_output")
    def test_missing_nic(self, check_output):
        """ Use mismatched double and single to test a mismatched nic """

        ctx = self.ctx_dry

        ctx.bond_test_data = DUAL_NIC_BOND
        check_output.return_value = SINGLE_NIC_LLDP

        with patch("time.sleep"):
            with self.assertRaises(ECBPSvcExc):
                for ifname in ctx.ingress_interfaces:
                    ctx.validate_vlans(ifname)

    @patch("subprocess.check_output")
    def test_bond_format_change(self, check_output):
        """ Make sure we raise on a muddled bond """

        ctx = self.ctx_dry

        ctx.bond_test_data = "MOO COWS"
        check_output.return_value = SINGLE_NIC_LLDP

        with patch("time.sleep"):
            with self.assertRaisesRegex(ECBPSvcExc, r"Failed to parse"):
                ctx.get_bond_ifnames(0)

    @patch("subprocess.check_output")
    def test_egress_bond(self, check_output):
        """ Make sure we get a vlan tagged bond0 """

        ctx = self.ctx_dry

        ctx.bond_test_data = SINGLE_NIC_BOND
        check_output.return_value = SINGLE_NIC_LLDP

        self.assertEqual(ctx.ingress_bond, "bond0")
        self.assertEqual(ctx.egress_bond, "bond1")

        with patch("os.path.exists", return_value=True):
            self.assertEqual(ctx.egress_bond, "bond0.10")

    @patch("subprocess.check_output")
    def test_egress_interfaces(self, check_output):
        """ Make sure we get the same interfaces when we have a tagged bond0 """

        ctx = self.ctx_dry

        ctx.bond_test_data = SINGLE_NIC_BOND
        check_output.return_value = SINGLE_NIC_LLDP

        with patch.object(ECBPFServiceHandler, "_has_tagged_egress", return_value=True) as mock:
            self.assertEqual(ctx.ingress_interfaces, ctx.egress_interfaces)
            mock.return_value = False
            self.assertNotEqual(ctx.ingress_interfaces, ctx.egress_interfaces)

    @patch("ecbpf_service_handler._getsrvinfo")
    @patch("subprocess.check_output")
    def test_dry_run(self, check_output, srvinfo):
        """ Make sure dry run doesn't run """

        ctx = self.ctx_dry
        srvinfo_res = {'subpurposes': 'director',
                        'ecdns-anycast-vips': '72.21.80.5 72.21.80.6 2606:2800:1::5 2606:2800:1::6'}
        srvinfo.side_effect = lambda k, d=None: srvinfo_res.get(k, d)

        with patch("os.execvp") as mock:
            for i in [ctx.xdp_root, ctx.xdp_sampler, ctx.xdp_bypass_ipvs]:
                for bond, lldp in [(SINGLE_NIC_BOND, SINGLE_NIC_LLDP),
                                   (DUAL_NIC_BOND, DUAL_NIC_LLDP)]:
                    ctx.bond_test_data = bond
                    check_output.return_value = lldp
                    i(start=True)

            self.assertFalse(mock.called)

    @patch("ecbpf_service_handler._getsrvinfo")
    @patch("subprocess.check_output")
    def test_run(self, check_output, srvinfo):
        """ Make sure run runs """

        ctx = self.ctx_dry
        ctx.dry_run = False
        ctx = self.ctx_dry
        srvinfo_res = {'subpurposes': 'director',
                       'ecdns-anycast-vips': '72.21.80.5 72.21.80.6 2606:2800:1::5 2606:2800:1::6'}
        srvinfo.side_effect = lambda k, d=None: srvinfo_res.get(k, d)

        with patch("os.execvp") as mock:
            for i in [ctx.xdp_root, ctx.xdp_sampler, ctx.xdp_bypass_ipvs]:
                for bond, lldp in [(SINGLE_NIC_BOND, SINGLE_NIC_LLDP),
                                   (DUAL_NIC_BOND, DUAL_NIC_LLDP)]:
                    ctx.bond_test_data = bond
                    check_output.return_value = lldp
                    i(start=True)

            self.assertTrue(mock.called)

    @patch("ecbpf_service_handler._getsrvinfo")
    @patch("os.path.exists", return_value=True)
    @patch("subprocess.check_output")
    def test_g9_bypass(self, check_output, _, srvinfo):
        """ Make sure we get the right command when using a single bond interface """

        expected_command = ['/usr/bin/taskset', '0x00005555', '/usr/bin/xdp_bypass_ipvs',
                            '-v', '10', '-L', '-i', 'eth2,eth0', '-o', 'bond0.10', '-a',
                            'bond0']
        ctx = self.ctx_dry
        ctx.dry_run = False

        ctx.bond_test_data = G9_BOND
        check_output.return_value = G9_LLDP
        srvinfo_res = {'subpurposes': 'director',
                       'ecdns-anycast-vips': '72.21.80.5 72.21.80.6 2606:2800:1::5 2606:2800:1::6'}
        srvinfo.side_effect = lambda k, d=None: srvinfo_res.get(k, d)

        with patch("os.execvp") as mock:
            ctx.xdp_bypass_ipvs(start=True)
            args, _ = mock.call_args
            command = args[1]
            self.assertTrue(mock.called)
            print(command)
            self.assertCountEqual(command, expected_command)

    @patch("ecbpf_service_handler._getsrvinfo")
    @patch("os.path.exists", return_value=False)
    @patch("subprocess.check_output")
    def test_g9_bypass_lldp(self, check_output, _, srvinfo):
        """ Make sure we check interfaces when bond0.10 doesn't exist (see patch above) """

        ctx = self.ctx_dry
        ctx.dry_run = False

        srvinfo_res = {'subpurposes': 'director',
                       'ecdns-anycast-vips': '72.21.80.5 72.21.80.6 2606:2800:1::5 2606:2800:1::6'}
        srvinfo.side_effect = lambda k, d=None: srvinfo_res.get(k, d)

        ctx.bond_test_data = G9_BOND
        check_output.return_value = G9_LLDP

        with patch("os.execvp"):
            with self.assertRaisesRegex(ECBPSvcExc, r"has only one VLAN"):
                ctx.xdp_bypass_ipvs(start=True)

    @patch("ecbpf_service_handler._getsrvinfo")
    @patch("os.path.exists", return_value=False)
    @patch("subprocess.check_output")
    def test_g8_arista_bypass(self, check_output, _, srvinfo):
        """ We need to skip VLAN validation (config override) for G8 Arista pops
        because the switch doesn't tell us about tagged VLANs """

        expected_command = ['/usr/bin/taskset', '0x00005555', '/usr/bin/xdp_bypass_ipvs',
                            '-v', '10', '-L', '-i', 'eth0,eth2', '-o', 'eth1,eth3', '-a',
                            'bond0,bond1']

        ctx = ECBPFServiceHandler()
        ctx.load_config("test-skip-vlan-check.conf")
        srvinfo_res = {'subpurposes': 'director',
                       'ecdns-anycast-vips': '72.21.80.5 72.21.80.6 2606:2800:1::5 2606:2800:1::6'}
        srvinfo.side_effect = lambda k, d=None: srvinfo_res.get(k, d)

        ctx.bond_test_data = DUAL_NIC_BOND
        check_output.return_value = G8_ARISTA_LLDP

        with patch("os.execvp") as mock:
            ctx.xdp_bypass_ipvs(start=True)
            args, _ = mock.call_args
            command = args[1]
            self.assertTrue(mock.called)
            print(command)
            self.assertCountEqual(command, expected_command)

    @patch("ecbpf_service_handler._getsrvinfo")
    @patch("os.path.exists", return_value=False)
    @patch("subprocess.check_output")
    def test_single_bypass(self, check_output, _, srvinfo):
        """ Make sure we get the right command when using a single bond interface """

        expected_command = ['/usr/bin/taskset', '0x00005555', '/usr/bin/xdp_bypass_ipvs',
                            '-v', '10', '-L', '-i', 'eth0', '-o', 'eth1', '-a',
                            'bond0,bond1']
        ctx = self.ctx_dry
        ctx.dry_run = False
        srvinfo_res = {'subpurposes': 'director',
                       'ecdns-anycast-vips': '72.21.80.5 72.21.80.6 2606:2800:1::5 2606:2800:1::6'}
        srvinfo.side_effect = lambda k, d=None: srvinfo_res.get(k, d)

        ctx.bond_test_data = SINGLE_NIC_BOND
        check_output.return_value = SINGLE_NIC_LLDP

        with patch("os.execvp") as mock:
            ctx.xdp_bypass_ipvs(start=True)
            args, _ = mock.call_args
            command = args[1]
            self.assertTrue(mock.called)
            print(command)
            self.assertCountEqual(command, expected_command)

    @patch("ecbpf_service_handler._getsrvinfo")
    @patch("os.path.exists", return_value=False)
    @patch("subprocess.check_output")
    def test_dnsa_subpurpose(self, check_output, _, srvinfo):
        """ Make sure we add dnsa vips to the address skip list """

        expected_command = ['/usr/bin/taskset', '0x00005555', '/usr/bin/xdp_bypass_ipvs',
                            '-v', '10', '-L', '-i', 'eth0', '-o', 'eth1', '-a',
                            'bond0,bond1', '-e', 'add',
                            '72.21.80.5,72.21.80.6,2606:2800:1::5,2606:2800:1::6']

        ctx = self.ctx_dry
        ctx.dry_run = False
        srvinfo_res = {'subpurposes': 'director dnsa',
                       'ecdns-anycast-vips': '72.21.80.5 72.21.80.6 2606:2800:1::5 2606:2800:1::6'}
        srvinfo.side_effect = lambda k, d=None: srvinfo_res.get(k, d)

        ctx.bond_test_data = SINGLE_NIC_BOND
        check_output.return_value = SINGLE_NIC_LLDP

        with patch("os.execvp") as mock:
            ctx.xdp_bypass_ipvs(start=True)
            args, _ = mock.call_args
            command = args[1]
            self.assertTrue(mock.called)
            print(command)
            self.assertCountEqual(command, expected_command)


if __name__ == '__main__':
    unittest.main()
