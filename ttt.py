from cas_pip.casclient.casclient import GRPCClient, Artifact, ArtifactType, ArtifactAuthorizationRequest

import datetime
import pytz
import asyncio

def getCurrentTime():
    now = datetime.datetime.utcnow() - datetime.timedelta(hours=100)
    pst_now = pytz.utc.localize(now)
    print(pst_now)
    return pst_now

toSign = Artifact(signer = "YWRhbUBjb2Rlbm90YXJ5LmNvbQ==",
hash = "43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1",
type = ArtifactType.Direct,
kind = "test",
name = "TESTER",
size = 100,
contentType= "application/zip",
metadata = {
    "test": 123
}, 
timestamp=getCurrentTime(),
status = 2,
Verbose=True,
PublicKey="ssdasd")
a = GRPCClient(api_key="YWRhbUBjb2Rlbm90YXJ5LmNvbQ==.VYOtpkwbfjTpybwaVkPvfvTODnHbGTHrjJCT")
# b = a.notarizeArtifact(toSign)
# print(b)

bb = asyncio.run(a.asyncNotarizeArtifact(toSign))
print(bb)
att = ArtifactAuthorizationRequest(
    signer = "YWRhbUBjb2Rlbm90YXJ5LmNvbQ==",
    hash = "43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1"
)
b = a.authorizeArtifact(artifact = toSign)