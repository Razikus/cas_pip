from enum import IntEnum
import asyncio
import logging
from typing import List
from pip._internal.cli.main import main as _main
import json

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
    
    async def notarizeFile(self, absolutePath, packageName):
        cmd = [self.casPath, "notarize", absolutePath, "--output=json", "--api-key", self.apiKey]
        stdout, stderr = await self.executeMe(cmd)
        if(stderr):
            self.logger.error(packageName + " " +  stderr.decode("utf-8"))
        return packageName, json.loads(stdout)


    async def authenticateFile(self, packageName, package):
        cmd = [self.casPath, "authenticate", package, "--output=json"]
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
        _main(args)