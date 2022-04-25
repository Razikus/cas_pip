import click
import tempfile
import asyncio
from functools import wraps
import os
import json
from enum import IntEnum
import sys
import logging
from pip._internal.cli.main import main as _main

logger = logging.getLogger("caspip")


class NotarizedStatus(IntEnum):
    NOTARIZED = 0
    UNTRUSTED = 1
    UNSUPPORTED = 3
    UNKNOWN = -1

def asynchronous(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper

async def executeMe(cmd):
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    await proc.wait()
    stdout, stderr = await proc.communicate()
    return stdout, stderr


async def notarizeIt(absolutePath, packageName):
    stdout, stderr = await executeMe(f"cas notarize {absolutePath} --output=json")
    if(stderr):
        logger.error(packageName + " " +  stderr)
    return packageName, stdout


async def authenticateIt(packageName, package):

    stdout, stderr = await executeMe(f"cas authenticate {package} --output=json")
    if(stderr):
        logger.error(packageName + " " +  stderr.decode("utf-8"))
    return packageName, stdout.decode("utf-8")



def downloadPipFiles(tmpDirectoryName, quiet = True, noCache = True, reqFile = "requirements.txt", additionalPipArgs = []):
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

@click.group()
def cli():
    pass

def chunks(lst, n):
    chunked = []
    for i in range(0, len(lst), n):
        chunked.append(lst[i:i + n])
    return chunked



@click.command()
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@asynchronous
async def authorize(reqfile, taskchunk, pipnoquiet, nocache):
    statusCodeToRet = 0
    with tempfile.TemporaryDirectory() as tmpdirname:
        downloadPipFiles(tmpdirname, reqFile = reqfile, quiet = pipnoquiet, noCache=nocache)
        filesIncluded = dict()
        tasks = []
        for file in os.walk(tmpdirname):
            for package in file[2]:
                filesIncluded[package] = os.path.join(file[0], package)
                tasks.append(authenticateIt(package, filesIncluded[package]))
        gathered = []

        chunked = chunks(tasks, taskchunk)
        with click.progressbar(chunked, label = f"Authorization") as bar:
            for chunk in bar:    
                gatheredChunk = await asyncio.gather(*chunk)
                gathered.extend(gatheredChunk)
        authorizedSbom = dict()
        for item in gathered:
            try:
                loaded = json.loads(item[1])
                status = NotarizedStatus(loaded["status"])
                authorizedSbom[item[0]] = status
                
                if(status == 0):
                    pass
                elif(status == 1):
                    statusCodeToRet = 1
                elif(status == 3):
                    statusCodeToRet = 1
                else:
                    statusCodeToRet = 1
            except:
                status = NotarizedStatus.UNKNOWN
                statusCodeToRet = 1
                authorizedSbom[item[0]] = status
        

        print(json.dumps(authorizedSbom, indent=4))
    sys.exit(statusCodeToRet)


@click.command()
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@asynchronous
async def notarize(reqfile, taskchunk, pipnoquiet, nocache):
    with tempfile.TemporaryDirectory() as tmpdirname:
        downloadPipFiles(tmpdirname, reqFile = reqfile, quiet=pipnoquiet, noCache=nocache)
        filesIncluded = dict()
        tasks = []
        for file in os.walk(tmpdirname):
            for package in file[2]:
                filesIncluded[package] = os.path.join(file[0], package)
                tasks.append(notarizeIt(filesIncluded[package], package))
        
        gathered = []
        chunked = chunks(tasks, taskchunk)
        with click.progressbar(chunked, label = f"Notarization") as bar:
            for chunk in bar:    
                gatheredChunk = await asyncio.gather(*chunk)
                gathered.extend(gatheredChunk)
        sbom = dict()
        for item in gathered:
            try:
                sbom[item[0]] = json.loads(item[1])
            except:
                logger.error("Something goes wrong with notarization of " + item[0])
                logger.error("Will not continue")
                sys.exit(1)

        print(json.dumps(sbom, indent=4))

def main():
    cli.add_command(authorize)
    cli.add_command(notarize)
    cli()

if __name__ == '__main__':
    main()

