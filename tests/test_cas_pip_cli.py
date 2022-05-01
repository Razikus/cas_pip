#!/usr/bin/env python

"""Tests for `cas_pip` package."""


import unittest
from click.testing import CliRunner

from cas_pip import cli
import os
import tempfile
import json
import hashlib
import pytest

signerID = os.environ.get("SIGNER_ID", "somesigner@signer")
apiKey = os.environ.get("CAS_API_KEY", "signing")



@pytest.mark.filterwarnings("ignore:Creating a LegacyVersion")
class TestCas_pip(unittest.TestCase):
    """Tests for `cas_pip` package."""

    def setUp(self):
        """Set up test fixtures, if any."""

    def tearDown(self):
        """Tear down test fixtures, if any."""

    def get_hash(self, of: str):
        hashed = hashlib.sha256()
        hashed.update(of.encode("utf-8"))
        return hashed.hexdigest()

    def test_command_line_interface(self):
        """Test the CLI."""
        runner = CliRunner()
        help_result = runner.invoke(cli.cli, ['--help'])
        assert help_result.exit_code == 0
        assert '--help  Show this message and exit.' in help_result.output
        assert 'authenticate' in help_result.output
        assert 'notarize' in help_result.output
    
    @pytest.mark.first
    def test_notarization(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            reqfile = os.path.join(tmpdir, "req.txt")
            packages = """
            Click==8.1.3
            """
            toOpen = open(reqfile, "w")
            toOpen.write(packages)
            toOpen.close()
            hashed = self.get_hash(packages)
            help_result = runner.invoke(cli.cli, ['notarize', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress"])
            print(help_result.stdout)
            assert help_result.exit_code == 0 
            jsoned = json.loads(help_result.output)["statuses"]
            assert jsoned["~NOTARIZED_REQ_FILE~"]["status"] == 0
            assert jsoned["~NOTARIZED_REQ_FILE~"]["hash"] == hashed

            assert "click-8.1.3-py3-none-any.whl" in jsoned


            packages = """
            Click==8.1.3
            websockets==8.1
            fastapi==0.75.2
            """
            toOpen = open(reqfile, "w")
            toOpen.write(packages)
            toOpen.close()
            hashed = self.get_hash(packages)
            
            help_result = runner.invoke(cli.cli, ['notarize', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress"])
            assert help_result.exit_code == 0 
            jsoned = json.loads(help_result.output)["statuses"]
            assert jsoned["~NOTARIZED_REQ_FILE~"]["status"] == 0
            assert jsoned["~NOTARIZED_REQ_FILE~"]["hash"] == hashed
            assert "websockets-8.1.tar.gz" in jsoned # package provided
            assert "click-8.1.3-py3-none-any.whl" in jsoned # package provided 
            assert "starlette-0.17.1-py3-none-any.whl" in jsoned # package dependend from fastapi
            
            help_result = runner.invoke(cli.cli, ['notarize', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress", "--output", "NONE"])
            assert help_result.exit_code == 0 
            assert help_result.output == ""

            
            help_result = runner.invoke(cli.cli, ['notarize', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress", "--output", "-"])
            assert help_result.exit_code == 0 
            assert len(json.loads(help_result.output)["statuses"].keys()) > 3

            help_result = runner.invoke(cli.cli, ['notarize', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress", "--output", "outputfile"])
            assert help_result.exit_code == 0 
            assert os.path.exists("outputfile")
            notarizedAll = open("outputfile", "r")
            jsoned = json.loads(notarizedAll.read())["statuses"]
            notarizedAll.close()

            assert "~NOTARIZED_REQ_FILE~" in jsoned
            assert jsoned["~NOTARIZED_REQ_FILE~"]["status"] == 0
            assert jsoned["~NOTARIZED_REQ_FILE~"]["hash"] == hashed
            assert "websockets-8.1.tar.gz" in jsoned # package provided
            assert "click-8.1.3-py3-none-any.whl" in jsoned # package provided 
            assert "starlette-0.17.1-py3-none-any.whl" in jsoned # package dependend from fastapi


            help_result = runner.invoke(cli.cli, ['notarize', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress", "--output", "outputfile", "--notarizepip"])
            assert help_result.exit_code == 0 
            assert os.path.exists("outputfile")
            notarizedAll = open("outputfile", "r")
            jsoned = json.loads(notarizedAll.read())["statuses"]
            notarizedAll.close()

            assert "~NOTARIZED_REQ_FILE~" in jsoned
            assert jsoned["~NOTARIZED_REQ_PIPVERSION~"]["status"] == 0
            assert jsoned["~NOTARIZED_REQ_FILE~"]["hash"] == hashed
            assert jsoned["~NOTARIZED_REQ_FILE~"]["status"] == 0
            assert "websockets-8.1.tar.gz" in jsoned # package provided
            assert "click-8.1.3-py3-none-any.whl" in jsoned # package provided 
            assert "starlette-0.17.1-py3-none-any.whl" in jsoned # package dependend from fastapi
    @pytest.mark.second
    def test_authorization(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            reqfile = os.path.join(tmpdir, "badreq.txt")
            packages = """
            asdasdasdasdadadasd
            """
            toOpen = open(reqfile, "w")
            toOpen.write(packages)
            toOpen.close()
            hashed = self.get_hash(packages)
            help_result = runner.invoke(cli.cli, ['notarize', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress"])
            assert help_result.exit_code == 1 

            reqfile = os.path.join(tmpdir, "req.txt")
            packages = """
            Click==8.1.3
            """
            toOpen = open(reqfile, "w")
            toOpen.write(packages)
            toOpen.close()
            hashed = self.get_hash(packages)
            help_result = runner.invoke(cli.cli, ['notarize', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress"])
            assert help_result.exit_code == 0 
            jsoned = json.loads(help_result.output)["statuses"]
            assert jsoned["~NOTARIZED_REQ_FILE~"]["status"] == 0
            assert jsoned["~NOTARIZED_REQ_FILE~"]["hash"] == hashed

            assert "click-8.1.3-py3-none-any.whl" in jsoned


            help_result = runner.invoke(cli.cli, ['authenticate', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress"])
            
            jsoned = json.loads(help_result.output)["statuses"]
            assert jsoned["~NOTARIZED_REQ_FILE~"] == 0
            assert jsoned["click-8.1.3-py3-none-any.whl"] == 0


            packages = """
            Click==8.1.3
            websockets==8.1
            fastapi==0.75.2
            """
            toOpen = open(reqfile, "w")
            toOpen.write(packages)
            toOpen.close()
            hashed = self.get_hash(packages)
            help_result = runner.invoke(cli.cli, ['authenticate', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress"])
            jsoned = json.loads(help_result.output)["statuses"]
            assert jsoned["~NOTARIZED_REQ_FILE~"] == 0
            assert jsoned["websockets-8.1.tar.gz"] == 0
            assert jsoned["click-8.1.3-py3-none-any.whl"] == 0
            assert jsoned["starlette-0.17.1-py3-none-any.whl"] == 0
            help_result = runner.invoke(cli.cli, ['authenticate', "--reqfile", reqfile, "--api-key", apiKey, "--noprogress", "--notarizepip"])
            jsoned = json.loads(help_result.output)["statuses"]
            assert jsoned["~NOTARIZED_REQ_PIPVERSION~"] == 0
            assert jsoned["~NOTARIZED_REQ_FILE~"] == 0
            assert jsoned["websockets-8.1.tar.gz"] == 0
            assert jsoned["click-8.1.3-py3-none-any.whl"] == 0
            assert jsoned["starlette-0.17.1-py3-none-any.whl"] == 0
            
            


