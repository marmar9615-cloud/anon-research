"""Tests for the platform-detection bits of setup. Pure logic — no shell calls."""
import unittest

import anon


class TestLinuxInstallHint(unittest.TestCase):
    def test_ubuntu(self):
        os_release = 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n'
        self.assertIn("apt-get install", anon._linux_install_hint(os_release))

    def test_debian(self):
        os_release = 'NAME="Debian GNU/Linux"\nID=debian\n'
        self.assertIn("apt-get install", anon._linux_install_hint(os_release))

    def test_fedora(self):
        os_release = 'NAME="Fedora Linux"\nID=fedora\nVERSION_ID=40\n'
        self.assertIn("dnf install", anon._linux_install_hint(os_release))

    def test_rocky_via_id_like(self):
        os_release = 'NAME="Rocky Linux"\nID=rocky\nID_LIKE="rhel centos fedora"\n'
        self.assertIn("dnf install", anon._linux_install_hint(os_release))

    def test_arch(self):
        os_release = 'NAME="Arch Linux"\nID=arch\n'
        self.assertIn("pacman", anon._linux_install_hint(os_release))

    def test_manjaro_via_id_like(self):
        os_release = 'NAME="Manjaro"\nID=manjaro\nID_LIKE=arch\n'
        self.assertIn("pacman", anon._linux_install_hint(os_release))

    def test_alpine(self):
        os_release = 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.20\n'
        self.assertIn("apk", anon._linux_install_hint(os_release))

    def test_unknown_falls_back_to_apt(self):
        os_release = 'NAME="Mystery OS"\nID=mystery\n'
        self.assertIn("apt-get install", anon._linux_install_hint(os_release))

    def test_empty_falls_back_to_apt(self):
        self.assertIn("apt-get install", anon._linux_install_hint(""))


if __name__ == "__main__":
    unittest.main()
