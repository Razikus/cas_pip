import logging
import aiofiles
from pip import __version__ as pipVersion
from pip._internal.cli.main import main as _main
import hashlib
from typing import Union, Dict, Optional, List
from enum import Enum
from pydantic import BaseModel, Field
import datetime
import grpc
import pytz
import mimetypes
from cas_pip.models import schema_pb2
from ..models import lc_pb2_grpc
import base64

class ArtifactType(Enum):
    Direct = 0
    Indirect = 1
    Base = 2

def getCurrentTime():
    now = datetime.datetime.utcnow()
    pst_now = pytz.utc.localize(now)
    return pst_now


class ArtifactStatus(Enum):
    TRUSTED = 0
    UNTRUSTED = 1
    UNKNOWN = 2
    UNSUPPORTED = 3
    REVOKED = 4
    
class ArtifactAuthorizationRequest(BaseModel):
    signer: str = None
    hash: str


class Artifact(BaseModel):
    signer: str = None
    hash: str
    type: Optional[ArtifactType]
    kind: str
    name: str
    size: int
    timestamp: datetime.datetime =  Field(default_factory=getCurrentTime)
    contentType: str
    metadata: Dict[str, Union[str, int, bool, float]]
    signer: str
    status: ArtifactStatus
    PublicKey: Optional[str]
    Verbose: bool = None

class ArtifactList(BaseModel):
    statuses: Dict[str, Artifact]

class ArtifactStatusList(BaseModel):
    statuses: Dict[str, ArtifactStatus]

class TransactionReturn(BaseModel):
    id: int
    prevAlh: bytes
    ts: int
    nentries: int
    eH: bytes
    blTxId: int
    blRoot: bytes
    version: int


class GRPCClient:
    def __init__(self, path: str = "cas.codenotary.com", api_key: str = None):
        self.path = path
        self.api_key = api_key
        self.signerId = api_key.split(".")[0]

    def _getSigningMetas(self):
        return [
            ("ledger", ""),
            ("lc-api-key", self.api_key),
            ("version", "1.0.2")
        ]
    def _getReadingMetas(self):
        return [
            ("plugin-type", "vcn")
        ]

    async def asyncNotarizeArtifact(self, *artifactsToSign: List[Artifact]):
        async with grpc.aio.secure_channel(self.path, grpc.ssl_channel_credentials()) as channel:
            stub = lc_pb2_grpc.LcServiceStub(channel)
            artifacts = []
            for artifact in artifactsToSign:
                if(artifact.signer == None):
                    artifact.signer = self.signerId
                vcndep = lc_pb2_grpc.lc__pb2.VCNDependency(hash=artifact.hash, type=ArtifactType.Direct.value)
                artifact = lc_pb2_grpc.lc__pb2.VCNArtifact(
                    dependencies=[vcndep],
                    artifact=artifact.json().encode("utf-8")
                )
                artifacts.append(artifact)
            req = lc_pb2_grpc.lc__pb2.VCNArtifactsRequest(artifacts=artifacts)
            try:
                metas = self._getSigningMetas()
                response = await stub.VCNSetArtifacts(req, metadata=metas)
                toRet = TransactionReturn(
                    id = response.transaction.id,
                    prevAlh = response.transaction.prevAlh,
                    ts = response.transaction.ts,
                    nentries= response.transaction.nentries,
                    eH = response.transaction.eH,
                    blTxId = response.transaction.blTxId,
                    blRoot = response.transaction.blRoot,
                    version = response.transaction.version
                )
                return True, toRet
            except grpc.RpcError as e:
                return False, e.details()

    async def asyncAuthorizeArtifact(self, artifact: ArtifactAuthorizationRequest):
        if(artifact.signer == None):
            artifact.signer = self.signerId
        async with grpc.aio.secure_channel(self.path, grpc.ssl_channel_credentials()) as channel:
            stub = lc_pb2_grpc.LcServiceStub(channel)
            keyRequest = schema_pb2.KeyRequest(
                key = self._getKeyForArtifact(artifact),
                atTx = 0
            )
            verfiableGet = schema_pb2.VerifiableGetRequest(
                keyRequest = keyRequest
            )
            try:
                metas = self._getReadingMetas()
                response = await stub.VerifiableGetExt(verfiableGet, metadata=metas)
                toRet = Artifact.parse_raw(response.item.entry.value)
                return True, toRet
            except grpc.RpcError as e:
                return False, e.details()

    def notarizeArtifact(self, *artifactsToSign: List[Artifact]):
        with grpc.secure_channel(self.path, grpc.ssl_channel_credentials()) as channel:
            stub = lc_pb2_grpc.LcServiceStub(channel)
            artifacts = []
            for artifact in artifactsToSign:
                if(artifact.signer == None):
                    artifact.signer = self.signerId
                vcndep = lc_pb2_grpc.lc__pb2.VCNDependency(hash=artifact.hash, type=ArtifactType.Direct.value)
                artifact = lc_pb2_grpc.lc__pb2.VCNArtifact(
                    dependencies=[vcndep],
                    artifact=artifact.json().encode("utf-8")
                )
                artifacts.append(artifact)
            req = lc_pb2_grpc.lc__pb2.VCNArtifactsRequest(artifacts=artifacts)
            try:
                metas = self._getSigningMetas()
                response = stub.VCNSetArtifacts(req, metadata=metas)
                toRet = TransactionReturn(
                    id = response.transaction.id,
                    prevAlh = response.transaction.prevAlh,
                    ts = response.transaction.ts,
                    nentries= response.transaction.nentries,
                    eH = response.transaction.eH,
                    blTxId = response.transaction.blTxId,
                    blRoot = response.transaction.blRoot,
                    version = response.transaction.version
                )
                return True, toRet
            except grpc.RpcError as e:
                return False, e.details()

    def _getKeyForArtifact(self, artifact: ArtifactAuthorizationRequest):
        what = f"vcn.{artifact.signer}.{artifact.hash}"
        return what.encode("utf-8")

    def authorizeArtifact(self, artifact: ArtifactAuthorizationRequest):
        if(artifact.signer == None):
            artifact.signer = self.signerId
        with grpc.secure_channel(self.path, grpc.ssl_channel_credentials()) as channel:
            stub = lc_pb2_grpc.LcServiceStub(channel)
            keyRequest = schema_pb2.KeyRequest(
                key = self._getKeyForArtifact(artifact),
                atTx = 0
            )
            verfiableGet = schema_pb2.VerifiableGetRequest(
                keyRequest = keyRequest
            )
            try:
                metas = self._getReadingMetas()
                response = stub.VerifiableGetExt(verfiableGet, metadata=metas)
                toRet = Artifact.parse_raw(response.item.entry.value)
                return True, toRet
            except grpc.RpcError as e:
                return False, e.details()

class CASClient:
    def __init__(self, signerId: str = None, apiKey: str = None, publicKey: str = None, casUrl: str = "cas.codenotary.com"):
        self.apiKey = apiKey
        self.signerId = signerId
        self.logger = logging.getLogger("caspip")
        apiKeyOrSigner = None
        if(apiKey):
            apiKeyOrSigner = apiKey
        else:
            apiKeyOrSigner = signerId
            try:
                what = base64.b64decode(apiKeyOrSigner).decode("utf-8")
            except:
                apiKeyOrSigner = base64.b64encode(apiKeyOrSigner.encode("utf-8")).decode("utf-8")

        self.publicKey = publicKey
        self.grpcClient = GRPCClient(casUrl, apiKeyOrSigner)

    def getSha256(self, fromWhat: Union[str, bytes], strEncoding = "utf-8"):
        hashed = hashlib.sha256()
        if(type(fromWhat) == str):
            hashed.update(fromWhat.encode(strEncoding))
        else:
            hashed.update(fromWhat)
        return hashed.hexdigest()
    
    async def generateHashFromFile(self, filePath: str) -> str:
        hashed = hashlib.sha256()
        size = 0
        async with aiofiles.open(filePath, mode="rb") as file:
            readed = await file.read(4096)
            while readed:
                size = size + len(readed)
                hashed.update(readed)
                readed = await file.read(4096)
        return hashed.hexdigest(), size

    async def notarizeHashWithStatus(self, hash, packageName, kind: str, contentType: str, size: int, artifactStatus: ArtifactStatus, metadata: Dict = dict()):
        artifact = Artifact(
                signer = None,
                hash = hash, 
                type = ArtifactType.Direct,
                kind = kind,
                name = packageName,
                size = size,
                contentType=contentType,
                metadata = metadata,
                status = artifactStatus,
                PublicKey=self.publicKey
            )
        status, transaction = await self.grpcClient.asyncNotarizeArtifact(artifact)
        if(status):
            return packageName, artifact
        else:
            return packageName, None

    async def notarizeHashAs(self, hash, packageName, status: ArtifactStatus):
        return await self.notarizeHashWithStatus(hash, packageName, "hash", "hash", 0, status)

    async def notarizeHash(self, hash, packageName):
        return await self.notarizeHashAs(hash, packageName, ArtifactStatus.TRUSTED)
    
    async def notarizeFileAs(self, absolutePath, packageName, status: ArtifactStatus):
        hash, fileSize = await self.generateHashFromFile(absolutePath)
        mimetype = mimetypes.guess_type(absolutePath)
        contentType = "application/octet-stream"
        if(mimetype and mimetype[0]):
            contentType = mimetype[0]
        return await self.notarizeHashWithStatus(hash, packageName, "file", contentType, fileSize, status)

    async def notarizeFile(self, absolutePath, packageName):
        return await self.notarizeFileAs(absolutePath, packageName, ArtifactStatus.TRUSTED)
    
    async def unsupportFile(self, absolutePath, packageName):
        return await self.notarizeFileAs(absolutePath, packageName, ArtifactStatus.UNSUPPORTED)

    async def unsupportHash(self, hash, packageName):
        return await self.notarizeHashAs(hash, packageName, ArtifactStatus.UNSUPPORTED)
    
    async def untrustFile(self, absolutePath, packageName):
        return await self.notarizeFileAs(absolutePath, packageName, ArtifactStatus.UNTRUSTED)

    async def untrustHash(self, hash, packageName):
        return await self.notarizeHashAs(hash, packageName, ArtifactStatus.UNTRUSTED)

    async def authenticateHash(self, hash, packageName):
        req = ArtifactAuthorizationRequest(hash = hash)
        authorized, status = await self.grpcClient.asyncAuthorizeArtifact(req)
        if(authorized):
            return packageName, status
        else:
            return packageName, None

    async def authenticateFile(self, absolutePath, packageName):
        hash, fileSize = await self.generateHashFromFile(absolutePath)
        req = ArtifactAuthorizationRequest(hash = hash)
        authorized, returned = await self.grpcClient.asyncAuthorizeArtifact(req)
        if(authorized):
            return packageName, returned
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