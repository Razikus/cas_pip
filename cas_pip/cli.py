import logging
import click
import tempfile
import asyncio
from functools import wraps
import os
import json
import sys
from .casclient.casclient import CASClient, NotarizedStatus

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
    pass

@cli.command(name="authorize", help = "Authorizes pip packages from provided requirements file")
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--caspath', default="cas", help='Path to cas binary')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@click.option('--signerid', help='Signer ID')
@click.option('--api-key', help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--noprogress',  default=False, is_flag = True, show_default = True, help='Shows progress bar of action')
@click.option('--notarizepip', default=False, is_flag = True, show_default = True, help='Notarizing also pip version')
@asynchronous
async def authorize(reqfile, taskchunk, caspath, pipnoquiet, nocache, signerid, api_key, output, noprogress, notarizepip):
    if(api_key == None and signerid == None):
        apikey = os.environ.get("CAS_API_KEY", None)
        signerid = os.environ.get("SIGNER_ID", None)
        if(apikey == None and signerid == None):
            logger.error("You must provide CAS_API_KEY or SIGNER_ID environment or --apikey argument or --signerid arugment to authorize")
            sys.exit(1)
    statusCodeToRet = 0
    casClient = CASClient(signerid, caspath, api_key)
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
            gathered.append(await casClient.notarizeHash(casClient.getSha256(casClient.getPipVersion()), notarizedReqPipVersion))
        for item in gathered:
            packageName, loaded = item
            if(loaded):
                status = NotarizedStatus(loaded["status"])
                authorizedSbom[packageName] = status.name
                statusCodeToRet = status.value
            else:
                status = NotarizedStatus.UNKNOWN
                statusCodeToRet = 1
                authorizedSbom[packageName] = status.name


        if(output == "-"):
            print(json.dumps(authorizedSbom, indent=4), flush=True)
        elif(output == "NONE"):
            pass
        else:
            with open(output, "w") as toWrite:
                toWrite.write(json.dumps(authorizedSbom, indent=4))
    sys.exit(statusCodeToRet)


@cli.command(name="notarize", help = "Notarizes pip packages from provided requirements file")
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--caspath', default="cas", help='Path to cas binary')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@click.option('--api-key', default=None, help='API Key')
@click.option('--output', default="-", help='Specifies output file. "-" for printing to stdout. NONE for printing nothing')
@click.option('--noprogress',  default=False, is_flag = True, show_default = True, help='Shows progress bar of action')
@click.option('--notarizepip', default=False, is_flag = True, show_default = True, help='Notarizing also pip version')
@asynchronous
async def notarize(reqfile, taskchunk, caspath, pipnoquiet, nocache, api_key, output, noprogress, notarizepip):
    if(api_key == None):
        api_key = os.environ.get("CAS_API_KEY", None)
        if(api_key == None):
            logger.error("You must provide CAS_API_KEY environment or --api_key argument")
            sys.exit(1)
    casClient = CASClient(None, caspath, api_key)
    with tempfile.TemporaryDirectory() as tmpdirname:
        pipStatus = casClient.downloadPipFiles(tmpdirname, reqFile = reqfile, quiet=pipnoquiet, noCache=nocache)
        if(not pipStatus):
            sys.exit(1)
        filesIncluded = dict()
        tasks = []
        for file in os.walk(tmpdirname):
            for package in file[2]:
                filesIncluded[package] = os.path.join(file[0], package)
                tasks.append(casClient.notarizeFile(filesIncluded[package], package))
        
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
                print(ee)
                casClient.logger.error("Something goes wrong with notarization of " + item[0])
                casClient.logger.error("Will not continue")
                sys.exit(1)
        name, notarization = await casClient.notarizeFile(reqfile, notarizedReqFilename)
        sbom[name] = notarization
        if(notarizepip):
            name, notarization = await casClient.notarizeHash(casClient.getSha256(casClient.getPipVersion()), notarizedReqPipVersion)
            sbom[name] = notarization

        if(output == "-"):
            print(json.dumps(sbom, indent=4), flush=True)
        elif(output == "NONE"):
            pass
        else:
            with open(output, "w") as toWrite:
                toWrite.write(json.dumps(sbom, indent=4))
        sys.exit(0)

def main():
    cli.add_command(authorize)
    cli.add_command(notarize)
    cli()

if __name__ == '__main__':
    main()

