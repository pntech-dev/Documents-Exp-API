import aioboto3
import logging
from fastapi import UploadFile, HTTPException
from botocore.exceptions import ClientError
from core.config import settings

logger = logging.getLogger(__name__)

class FileStorageService:
    def __init__(self):
        self.session = aioboto3.Session()
        self.bucket_name = settings.S3_BUCKET_NAME
        self.endpoint_url = settings.S3_ENDPOINT_URL
        self.aws_access_key_id = settings.S3_ACCESS_KEY
        self.aws_secret_access_key = settings.S3_SECRET_KEY
        logger.info(f"S3 Init: Endpoint={self.endpoint_url}, Key={self.aws_access_key_id}")

    async def upload_file(self, file: UploadFile, object_name: str) -> None:
        """Uploads a file-like object to S3."""
        try:
            async with self.session.client(
                "s3",
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
            ) as s3:
                # UploadFile.file is a SpooledTemporaryFile, which is file-like
                await s3.upload_fileobj(file.file, self.bucket_name, object_name)
        except ClientError as e:
            logger.error(f"S3 Upload Error: {e}")
            raise HTTPException(status_code=500, detail="Failed to upload file to storage")

    async def delete_file(self, object_name: str) -> None:
        """Deletes a file from S3."""
        try:
            async with self.session.client(
                "s3",
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
            ) as s3:
                await s3.delete_object(Bucket=self.bucket_name, Key=object_name)
        except ClientError as e:
            logger.error(f"S3 Delete Error: {e}")
            # We log but don't raise, to allow DB cleanup to proceed
            
    async def download_file_iterator(self, object_name: str):
        """
        Returns an async iterator of the file body.
        Used for StreamingResponse in FastAPI.
        """
        session = aioboto3.Session()
        async with session.client(
            "s3",
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
        ) as s3:
            try:
                response = await s3.get_object(Bucket=self.bucket_name, Key=object_name)
                async for chunk in response['Body']:
                    yield chunk
            except ClientError as e:
                logger.error(f"S3 Download Error: {e}")
                raise HTTPException(status_code=404, detail="File not found in storage")