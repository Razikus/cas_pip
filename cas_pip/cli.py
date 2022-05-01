import logging
import click
import tempfile
import asyncio
from functools import wraps
import os
import sys
from .casclient.casclient import CASClient, ArtifactStatus, ArtifactList, ArtifactStatusList

notarizedReqFilename = "~NOTARIZED_REQ_FILE~"
notarizedReqPipVersion = "~NOTARIZED_REQ_PIPVERSION~"

logger = logging.getLogger("cas_pip_cli")


def chunks(lst, n):
    chunked = []
    for i in range(0, len(lst), n):
        chunked.append(lst[i:i + n])
    return chunked

def asynchronous(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper

@click.group()
def cli():
    """Trusted - 0, Untrusted - 1, Unknown - 2, Unsupported - 3, Revoked - 4"""
    pass


async def markPipBomAs(casClient: CASClient, reqfile, taskchunk, pipnoquiet, nocache, noprogress, notarizepip, status: ArtifactStatus):
    with tempfile.TemporaryDirectory() as tmpdirname:
        pipStatus = casClient.downloadPipFiles(tmpdirname, reqFile = reqfile, quiet=pipnoquiet, noCache=nocache)
        if(not pipStatus):
            return None
        filesIncluded = dict()
        tasks = []
        for file in os.walk(tmpdirname):
            for package in file[2]:
                filesIncluded[package] = os.path.join(file[0], package)
                tasks.append(casClient.notarizeFileAs(filesIncluded[package], package, status))
        
        gathered = []
        chunked = chunks(tasks, taskchunk)
        if(not noprogress):
            with click.progressbar(chunked, label = f"Notarization") as bar:
                for chunk in bar:    
                    gatheredChunk = await asyncio.gather(*chunk)
                    gathered.extend(gatheredChunk)
        else:
            for chunk in chunked:    
                gatheredChunk = await asyncio.gather(*chunk)
                gathered.extend(gatheredChunk)

        sbom = dict()
        for item in gathered:
            try:
                sbom[item[0]] = item[1]
            except Exception as ee:
                casClient.logger.error("Something goes wrong with notarization of " + item[0])
                casClient.logger.error("Will not continue")
                return None
        name, notarization = await casClient.notarizeFileAs(reqfile, notarizedReqFilename, status)
        sbom[name] = notarization
        if(notarizepip):
            name, notarization = await casClient.notarizeHashAs(casClient.getSha256(casClient.getPipVersion()), notarizedReqPipVersion, status)
            sbom[name] = notarization
        listOf = ArtifactList(statuses = sbom)
        return listOf

@cli.command(name="authenticate", help = "Authenticate pip packages from provided requirements file")
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@click.option('--signerid', help='Signer ID')
@click.option('--api-key', help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--noprogress',  default=False, is_flag = True, show_default = True, help='Shows progress bar of action')
@click.option('--notarizepip', default=False, is_flag = True, show_default = True, help='Notarizing also pip version')
@asynchronous
async def authenticate(reqfile, taskchunk, pipnoquiet, nocache, signerid, api_key, output, noprogress, notarizepip):
    "Authenticate pip requirements.txt"
    if(api_key == None and signerid == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        signerid = os.environ.get("SIGNER_ID", None)
        if(api_key == None and signerid == None):
            logger.error("You must provide CAS_API_KEY or SIGNER_ID environment or --apikey argument or --signerid arugment to authorize")
            sys.exit(1)
    statusCodeToRet = 0
    casClient = CASClient(signerid, api_key)
    with tempfile.TemporaryDirectory() as tmpdirname:
        pipStatus = casClient.downloadPipFiles(tmpdirname, reqFile = reqfile, quiet = pipnoquiet, noCache=nocache)
        if(not pipStatus):
            sys.exit(1)
        filesIncluded = dict()
        tasks = []
        for file in os.walk(tmpdirname):
            for package in file[2]:
                filesIncluded[package] = os.path.join(file[0], package)
                tasks.append(casClient.authenticateFile(filesIncluded[package], package))
        gathered = []

        chunked = chunks(tasks, taskchunk)
        if(not noprogress):
            with click.progressbar(chunked, label = f"Authorization") as bar:
                for chunk in bar:    
                    gatheredChunk = await asyncio.gather(*chunk)
                    gathered.extend(gatheredChunk)
        else:
            for chunk in chunked:    
                gatheredChunk = await asyncio.gather(*chunk)
                gathered.extend(gatheredChunk)

        authorizedSbom = dict()
        gathered.append(await casClient.authenticateFile(reqfile, notarizedReqFilename))
        if(notarizepip):
            gathered.append(await casClient.authenticateHash(casClient.getSha256(casClient.getPipVersion()), notarizedReqPipVersion))
        for item in gathered:
            packageName, loaded = item
            if(loaded):
                status = loaded.status
                authorizedSbom[packageName] = status
                if(status.value > 0):
                    statusCodeToRet = status.value
            else:
                status = ArtifactStatus.UNKNOWN
                statusCodeToRet = 1
                authorizedSbom[packageName] = status

        listOf = ArtifactStatusList(statuses = authorizedSbom).json()
        if(output == "-"):
            print(listOf)
        elif(output == "NONE"):
            pass
        else:
            with open(output, "w") as toWrite:
                toWrite.write(listOf)
    sys.exit(statusCodeToRet)

@cli.command(name="notarize", help = "Notarizes pip packages from provided requirements file")
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@click.option('--api-key', default=None, help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--noprogress',  default=False, is_flag = True, show_default = True, help='Shows progress bar of action')
@click.option('--notarizepip', default=False, is_flag = True, show_default = True, help='Notarizing also pip version')
@asynchronous
async def notarize(reqfile, taskchunk, pipnoquiet, nocache, api_key, output, noprogress, notarizepip):
    if(api_key == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        if(api_key == None):
            logger.error("You must provide CAS_API_KEY environment or --api_key argument")
            sys.exit(1)
    casClient = CASClient(None, api_key)
    listOf = await markPipBomAs(casClient, reqfile, taskchunk, pipnoquiet, nocache, noprogress, notarizepip, ArtifactStatus.TRUSTED)
    if(not listOf):
        sys.exit(1)
    if(output == "-"):
        print(listOf.json(indent= 4), flush=True)
        sys.exit(0)
    elif(output == "NONE"):
        pass
    else:
        with open(output, "w") as toWrite:
            toWrite.write(listOf.json(indent= 4))
    sys.exit(0)



@cli.command(name="notarizeFile", help = "Notarizes file")
@click.option('--api-key', default=None, help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--asname', default=None, help='Specifies name of resource. Defaults - filename')
@click.argument("filename")
@asynchronous
async def notarizeFile(api_key, output, asname, filename):
    if not asname:
        asname = os.path.basename(filename)
    if(api_key == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        if(api_key == None):
            logger.error("You must provide CAS_API_KEY environment or --api_key argument")
            sys.exit(1)
    casClient = CASClient(None, api_key)
    status, artifact = await casClient.notarizeFileAs(filename, asname, ArtifactStatus.TRUSTED)
    if(not status):
        sys.exit(1)
    if(output == "-"):
        print(artifact.json(indent= 4), flush=True)
        sys.exit(0)
    elif(output == "NONE"):
        pass
    else:
        with open(output, "w") as toWrite:
            toWrite.write(artifact.json(indent= 4))
    sys.exit(0)

@cli.command(name="untrustFile", help = "Untrusts file")
@click.option('--api-key', default=None, help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--asname', default=None, help='Specifies name of resource. Defaults - filename')
@click.argument("filename")
@asynchronous
async def untrustFile(api_key, output, asname, filename):
    if not asname:
        asname = os.path.basename(filename)
    if(api_key == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        if(api_key == None):
            logger.error("You must provide CAS_API_KEY environment or --api_key argument")
            sys.exit(1)
    casClient = CASClient(None, api_key)
    status, artifact = await casClient.notarizeFileAs(filename, asname, ArtifactStatus.UNTRUSTED)
    if(not status):
        sys.exit(1)
    if(output == "-"):
        print(artifact.json(indent= 4), flush=True)
        sys.exit(0)
    elif(output == "NONE"):
        pass
    else:
        with open(output, "w") as toWrite:
            toWrite.write(artifact.json(indent= 4))
    sys.exit(0)


@cli.command(name="unsupportFile", help = "Unsupports file")
@click.option('--api-key', default=None, help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--asname', default=None, help='Specifies name of resource. Defaults - filename')
@click.argument("filename")
@asynchronous
async def unsupportFile(api_key, output, asname, filename):
    if not asname:
        asname = os.path.basename(filename)
    if(api_key == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        if(api_key == None):
            logger.error("You must provide CAS_API_KEY environment or --api_key argument")
            sys.exit(1)
    casClient = CASClient(None, api_key)
    status, artifact = await casClient.notarizeFileAs(filename, asname, ArtifactStatus.UNSUPPORTED)
    if(not status):
        sys.exit(1)
    if(output == "-"):
        print(artifact.json(indent= 4), flush=True)
        sys.exit(0)
    elif(output == "NONE"):
        pass
    else:
        with open(output, "w") as toWrite:
            toWrite.write(artifact.json(indent= 4))
    sys.exit(0)

@cli.command(name="authenticateFile", help = "Notarizes file")
@click.option('--api-key', default=None, help='API Key')
@click.option('--signerid', help='Signer ID')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.argument("filename")
@asynchronous
async def authenticateFile(api_key, signerid, output, filename):
    if(api_key == None and signerid == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        signerid = os.environ.get("SIGNER_ID", None)
        if(api_key == None and signerid == None):
            logger.error("You must provide CAS_API_KEY or SIGNER_ID environment or --apikey argument or --signerid arugment to authorize")
            sys.exit(1)
    statusCodeToRet = 0
    casClient = CASClient(signerid, api_key)
    status, artifact = await casClient.authenticateFile(filename, ArtifactStatus.TRUSTED)
    if(not status):
        sys.exit(1)
    authorizedSbom = dict()
    if(artifact):
        status = artifact.status
        authorizedSbom[artifact.name] = status
        if(status.value > 0):
            print("X")
            statusCodeToRet = status.value
    else:
        status = ArtifactStatus.UNKNOWN
        statusCodeToRet = 1
        authorizedSbom[filename] = status
        
    listOf = ArtifactStatusList(statuses = authorizedSbom)
    if(output == "-"):
        print(listOf.json(indent= 4), flush=True)
    elif(output == "NONE"):
        pass
    else:
        with open(output, "w") as toWrite:
            toWrite.write(listOf.json(indent= 4))
    sys.exit(statusCodeToRet)

@cli.command(name="untrust", help = "Untrust pip packages from provided requirements file")
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@click.option('--api-key', default=None, help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--noprogress',  default=False, is_flag = True, show_default = True, help='Shows progress bar of action')
@click.option('--notarizepip', default=False, is_flag = True, show_default = True, help='Notarizing also pip version')
@asynchronous
async def untrust(reqfile, taskchunk, pipnoquiet, nocache, api_key, output, noprogress, notarizepip):
    if(api_key == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        if(api_key == None):
            logger.error("You must provide CAS_API_KEY environment or --api_key argument")
            sys.exit(1)
    casClient = CASClient(None, api_key)
    listOf = await markPipBomAs(casClient, reqfile, taskchunk, pipnoquiet, nocache, noprogress, notarizepip, ArtifactStatus.UNTRUSTED)
    if(not listOf):
        sys.exit(1)
    if(output == "-"):
        print(listOf.json(indent= 4), flush=True)
        sys.exit(0)
    elif(output == "NONE"):
        pass
    else:
        with open(output, "w") as toWrite:
            toWrite.write(listOf.json(indent= 4))
    sys.exit(0)

@cli.command(name="unsupport", help = "Unsupports pip packages from provided requirements file")
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@click.option('--api-key', default=None, help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--noprogress',  default=False, is_flag = True, show_default = True, help='Shows progress bar of action')
@click.option('--notarizepip', default=False, is_flag = True, show_default = True, help='Notarizing also pip version')
@asynchronous
async def unsupport(reqfile, taskchunk, pipnoquiet, nocache, api_key, output, noprogress, notarizepip):
    if(api_key == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        if(api_key == None):
            logger.error("You must provide CAS_API_KEY environment or --api_key argument")
            sys.exit(1)
    casClient = CASClient(None, api_key)
    listOf = await markPipBomAs(casClient, reqfile, taskchunk, pipnoquiet, nocache, noprogress, notarizepip, ArtifactStatus.UNSUPPORTED)
    if(not listOf):
        sys.exit(1)
    if(output == "-"):
        print(listOf.json(indent= 4), flush=True)
        sys.exit(0)
    elif(output == "NONE"):
        pass
    else:
        with open(output, "w") as toWrite:
            toWrite.write(listOf.json(indent= 4))
    sys.exit(0)

def main():
    cli.add_command(authenticate)
    cli.add_command(notarize)
    cli()

if __name__ == '__main__':
    main()

