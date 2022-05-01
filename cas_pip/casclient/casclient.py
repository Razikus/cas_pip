from enum import IntEnum
import asyncio
import logging
from typing import List
from pip import __version__ as pipVersion
from pip._internal.cli.main import main as _main
import json
import hashlib
from typing import Union

class NotarizedStatus(IntEnum):
    NOTARIZED = 0
    UNTRUSTED = 1
    UNSUPPORTED = 3
    UNKNOWN = -1



class CASClient:
    def __init__(self, signerId: str = None, casPath: str = "cas",  apiKey: str = None):
        self.casPath = casPath
        self.apiKey = apiKey
        self.signerId = signerId
        self.logger = logging.getLogger("caspip")

    async def executeMe(self, cmd):
        proc = await asyncio.create_subprocess_exec(
            cmd[0], *cmd[1:],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        await proc.wait()
        stdout, stderr = await proc.communicate()
        return stdout, stderr

    def getSha256(self, fromWhat: Union[str, bytes], strEncoding = "utf-8"):
        hashed = hashlib.sha256()
        if(type(fromWhat) == str):
            hashed.update(fromWhat.encode(strEncoding))
        else:
            hashed.update(fromWhat)
        return hashed.hexdigest()

    async def notarizeHash(self, hash, packageName):
        cmd = [self.casPath, "notarize", "--hash", hash, "--output=json", "--api-key", self.apiKey, "--name", packageName]
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        return packageName, json.loads(stdout)
    
    async def notarizeFile(self, absolutePath, packageName):
        cmd = [self.casPath, "notarize", absolutePath, "--output=json", "--api-key", self.apiKey, "--name", packageName]
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        return packageName, json.loads(stdout)

    async def notarizeHash(self, hash, packageName):
        cmd = [self.casPath, "notarize", "--hash", hash, "--output=json", "--api-key", self.apiKey, "--name", packageName]
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        return packageName, json.loads(stdout)
    
    async def unsupportFile(self, absolutePath, packageName):
        cmd = [self.casPath, "unsupport", absolutePath, "--output=json", "--api-key", self.apiKey, "--name", packageName]
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        return packageName, json.loads(stdout)

    async def unsupportHash(self, hash, packageName):
        cmd = [self.casPath, "unsupport", "--hash", hash, "--output=json", "--api-key", self.apiKey, "--name", packageName]
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        return packageName, json.loads(stdout)
    
    async def untrustFile(self, absolutePath, packageName):
        cmd = [self.casPath, "untrust", absolutePath, "--output=json", "--api-key", self.apiKey, "--name", packageName]
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        return packageName, json.loads(stdout)

    async def untrustHash(self, hash, packageName):
        cmd = [self.casPath, "untrust", "--hash", hash, "--output=json", "--api-key", self.apiKey, "--name", packageName]
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        return packageName, json.loads(stdout)

    async def authenticateHash(self, hash, packageName):
        cmd = [self.casPath, "authenticate", "--hash", hash, "--output=json"]
        if(self.apiKey):
            cmd.append("--api-key"), 
            cmd.append(self.apiKey)
        elif(self.signerId):
            cmd.append("--signerID"), 
            cmd.append(self.signerId)
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        if(stdout):
            return packageName, json.loads(stdout)
        else:
            return packageName, None

    async def authenticateFile(self, absolutePath, packageName):
        cmd = [self.casPath, "authenticate", absolutePath, "--output=json"]
        if(self.apiKey):
            cmd.append("--api-key"), 
            cmd.append(self.apiKey)
        elif(self.signerId):
            cmd.append("--signerID"), 
            cmd.append(self.signerId)
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        if(stdout):
            return packageName, json.loads(stdout)
        else:
            return packageName, None

    def downloadPipFiles(self, tmpDirectoryName, quiet = True, noCache = True, reqFile = "requirements.txt", additionalPipArgs = []):
        args = ["download", "-d", tmpDirectoryName]
        if(noCache):
            args.append("--no-cache-dir")
        if(quiet):
            args.append("-q")
        if(reqFile):
            args.append("-r")
            args.append(reqFile)
        args.extend(additionalPipArgs)
        what = _main(args)
        return what == 0

    def getPipVersion(self):
        return pipVersion