from cas_pip.casclient.casclient import CASClient
import asyncio
import sys


apikey = sys.argv[1]

async def main():
    client = CASClient(None, apikey)
    sha = client.getSha256("blablabla")
    status, returned = await client.authenticateHash(sha, "mysuperhash")
    print(status, returned) # mysuperhash, None

    if not returned: # Asset not notarized
        status, returned = await client.notarizeHash(sha, "mysuperhash")
        print(status, returned) # mysuperhash, artifact details
    else:
        print("Asset already notarized")
    status, returned = await client.untrustHash(sha, "mysuperhash")
    print(status, returned)

    status, returned = await client.authenticateHash(sha, "mysuperhash")
    print(status, returned.status) # mysuperhash, status ArtifactStatus.Untrusted


asyncio.run(main())