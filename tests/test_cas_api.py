from tempfile import tempdir
from cas_pip.casclient.casclient import CASClient, ArtifactStatus, Artifact
import os
import pytest
import tempfile
import hashlib
import uuid
import time 
signerID = os.environ.get("SIGNER_ID", "yoursigner")
apiKey = os.environ.get("CAS_API_KEY", "yourkey")


@pytest.mark.asyncio
async def test_end_to_end_files():
    writeContent = str(uuid.uuid4()) + str(time.time())
    shaFrom = hashlib.sha256()
    shaFrom.update(writeContent.encode("utf-8"))
    shaFromDigest = shaFrom.hexdigest()
    client = CASClient(signerID, apiKey)
    # Notarization 
    with tempfile.TemporaryDirectory() as tmpDir:
        absolute = os.path.join(tmpDir, "test")
        toWrite = open(os.path.join(tmpDir, "test"), "w")
        
        toWrite.write(writeContent)
        
        toWrite.close()
        name, status = await client.notarizeFile(absolute, "totest")
        assert name == 'totest'
        assert status.status == ArtifactStatus.TRUSTED
        assert status.hash == shaFromDigest

    # Authentication of good
    with tempfile.TemporaryDirectory() as tmpDir:
        absolute = os.path.join(tmpDir, "test")
        toWrite = open(os.path.join(tmpDir, "test"), "w")
        toWrite.write(writeContent)
        toWrite.close()
        name, status = await client.authenticateFile(absolute, "totest")
        print(name, status)
        assert name == 'totest'
        assert status.status == ArtifactStatus.TRUSTED

    writeContentBad = str(time.time()) + str(uuid.uuid4())
    # Not notarized file case
    with tempfile.TemporaryDirectory() as tmpDir:
        absolute = os.path.join(tmpDir, "test")
        toWrite = open(os.path.join(tmpDir, "test"), "w")
        toWrite.write(writeContentBad)
        
        toWrite.close()
        name, status = await client.authenticateFile(absolute, "totest")
        assert status == None
        assert name == 'totest'

    # Untrusting
    with tempfile.TemporaryDirectory() as tmpDir:
        absolute = os.path.join(tmpDir, "test")
        toWrite = open(os.path.join(tmpDir, "test"), "w")
        toWrite.write(writeContent)
        
        toWrite.close()
        name, status = await client.untrustFile(absolute, "totest")
        assert status.hash == shaFromDigest
        assert name == 'totest'
    

    # Authentication of untrusted
    with tempfile.TemporaryDirectory() as tmpDir:
        absolute = os.path.join(tmpDir, "test")
        toWrite = open(os.path.join(tmpDir, "test"), "w")
        toWrite.write(writeContent)
        toWrite.close()
        name, status = await client.authenticateFile(absolute, "totest")
        print(name, status)
        assert name == 'totest'
        assert status.status == ArtifactStatus.UNTRUSTED

    # Unsupport
    with tempfile.TemporaryDirectory() as tmpDir:
        absolute = os.path.join(tmpDir, "test")
        toWrite = open(os.path.join(tmpDir, "test"), "w")
        toWrite.write(writeContent)
        
        toWrite.close()
        name, status = await client.unsupportFile(absolute, "totest")
        assert status.hash == shaFromDigest
        assert name == 'totest'
    

    # Authentication of unsupported
    with tempfile.TemporaryDirectory() as tmpDir:
        absolute = os.path.join(tmpDir, "test")
        toWrite = open(os.path.join(tmpDir, "test"), "w")
        toWrite.write(writeContent)
        toWrite.close()
        name, status = await client.authenticateFile(absolute, "totest")
        print(name, status)
        assert name == 'totest'
        assert status.status ==  ArtifactStatus.UNSUPPORTED



@pytest.mark.asyncio
async def test_end_to_end_hashes():
    writeContent = str(uuid.uuid4()) + str(time.time())
    shaFrom = hashlib.sha256()
    shaFrom.update(writeContent.encode("utf-8"))
    shaFromDigest = shaFrom.hexdigest()
    client = CASClient(signerID, apiKey)

    writeContentBad = str(uuid.uuid4()) + str(time.time())
    shaFrom = hashlib.sha256()
    shaFrom.update(writeContent.encode("utf-8"))
    shaFromDigestBad = shaFrom.hexdigest()

    package, what = await client.notarizeHash(shaFromDigest, "test")
    assert what.status == ArtifactStatus.TRUSTED
    assert what.hash == shaFromDigest


    package, what = await client.authenticateHash(shaFromDigest, "test")
    assert what.status == ArtifactStatus.TRUSTED
    assert what.hash == shaFromDigest


    package, what = await client.authenticateHash(shaFromDigest + "x", "test")
    assert type(what) != Artifact
    assert what == None

    package, what = await client.untrustHash(shaFromDigest, "test")
    assert what.status == ArtifactStatus.UNTRUSTED
    assert what.hash == shaFromDigest

    package, what = await client.authenticateHash(shaFromDigest, "test")
    assert what.status == ArtifactStatus.UNTRUSTED
    assert what.hash == shaFromDigest

    package, what = await client.unsupportHash(shaFromDigest, "test")
    assert what.status == ArtifactStatus.UNSUPPORTED
    assert what.hash == shaFromDigest

    package, what = await client.authenticateHash(shaFromDigest, "test")
    assert what.status == ArtifactStatus.UNSUPPORTED
    assert what.hash == shaFromDigest


