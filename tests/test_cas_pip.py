#!/usr/bin/env python

"""Tests for `cas_pip` package."""


import unittest
from click.testing import CliRunner

from cas_pip import cas_pip
from cas_pip import cli


class TestCas_pip(unittest.TestCase):
    """Tests for `cas_pip` package."""

    def setUp(self):
        """Set up test fixtures, if any."""

    def tearDown(self):
        """Tear down test fixtures, if any."""

    def test_000_something(self):
        """Test something."""

    def test_command_line_interface(self):
        """Test the CLI."""
        runner = CliRunner()
        result = runner.invoke(cli.main)
        assert result.exit_code == 0
        assert 'cas_pip.cli.main' in result.output
        help_result = runner.invoke(cli.main, ['--help'])
        assert help_result.exit_code == 0
        assert '--help  Show this message and exit.' in help_result.output
