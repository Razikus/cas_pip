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




@click.command()
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--caspath', default="cas", help='Path to cas binary')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@click.option('--signerid', help='Signer ID')
@click.option('--apikey', help='API Key')
@click.option('--output', default="-", help='Specifies output file "-" for printing to stdout')
@asynchronous
async def authorize(reqfile, taskchunk, caspath, pipnoquiet, nocache, signerid, apikey, output):
    if(apikey == None and signerid == None):
        apikey = os.environ.get("CAS_API_KEY", None)
        signerid = os.environ.get("SIGNER_ID", None)
        if(apikey == None and signerid == None):
            logger.error("You must provide CAS_API_KEY or SIGNER_ID environment or --apikey argument or --signerid arugment to authorize")
            sys.exit(1)
    statusCodeToRet = 0
    casClient = CASClient(signerid, caspath, apikey)
    with tempfile.TemporaryDirectory() as tmpdirname:
        casClient.downloadPipFiles(tmpdirname, reqFile = reqfile, quiet = pipnoquiet, noCache=nocache)
        filesIncluded = dict()
        tasks = []
        for file in os.walk(tmpdirname):
            for package in file[2]:
                filesIncluded[package] = os.path.join(file[0], package)
                tasks.append(casClient.authenticateFile(package, filesIncluded[package]))
        gathered = []

        chunked = chunks(tasks, taskchunk)
        with click.progressbar(chunked, label = f"Authorization") as bar:
            for chunk in bar:    
                gatheredChunk = await asyncio.gather(*chunk)
                gathered.extend(gatheredChunk)
        authorizedSbom = dict()
        gathered.append(await casClient.authenticateFile(notarizedReqFilename, reqfile))
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
        else:
            with open(output, "w") as toWrite:
                toWrite.write(json.dumps(authorizedSbom, indent=4))
    sys.exit(statusCodeToRet)


@click.command()
@click.option('--reqfile', default="requirements.txt", help='Requirements file name')
@click.option('--taskchunk', default=3, help='Max authorization request per once')
@click.option('--caspath', default="cas", help='Path to cas binary')
@click.option('--pipnoquiet', default=True, is_flag = True, show_default = True, help='Disables output of pip')
@click.option('--nocache', default=True, is_flag = True, show_default = True, help='Disables cache of pip')
@click.option('--apikey', default=None, help='API Key')
@click.option('--output', default="-", help='Specifies output file "-" for printing to stdout')
@asynchronous
async def notarize(reqfile, taskchunk, caspath, pipnoquiet, nocache, apikey, output):
    if(apikey == None):
        apikey = os.environ.get("CAS_API_KEY", None)
        if(apikey == None):
            logger.error("You must provide CAS_API_KEY environment or --apikey argument")
            sys.exit(1)
    casClient = CASClient(None, caspath, apikey)
    with tempfile.TemporaryDirectory() as tmpdirname:
        casClient.downloadPipFiles(tmpdirname, reqFile = reqfile, quiet=pipnoquiet, noCache=nocache)
        filesIncluded = dict()
        tasks = []
        for file in os.walk(tmpdirname):
            for package in file[2]:
                filesIncluded[package] = os.path.join(file[0], package)
                tasks.append(casClient.notarizeFile(filesIncluded[package], package))
        
        gathered = []
        chunked = chunks(tasks, taskchunk)
        with click.progressbar(chunked, label = f"Notarization") as bar:
            for chunk in bar:    
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
        if(output == "-"):
            print(json.dumps(sbom, indent=4), flush=True)
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

