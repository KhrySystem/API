from json import loads
from functools import lru_cache
from os import getenv
from typing import Any

import boto3 as aws
from botocore.exceptions import ClientError


@lru_cache
def get_aws_secret_raw(aws_server: str, secret_name: str) -> 'dict[str, Any]':
    session = aws.session.Session(
        aws_access_key_id = getenv('AWS_ACCESS_KEY'),
        aws_secret_access_key=getenv('AWS_SECRET_KEY')
    )
    client = session.client(
        service_name='secretsmanager',
        region_name=aws_server,
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print("The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
        else:
            raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secrets = get_secret_value_response['SecretString']
        else:
            secrets = get_secret_value_response['SecretBinary']
        return secrets

def get_aws_secret(aws_server: str, secret_name: str, token_name: str) -> str:
        secrets = loads(get_aws_secret_raw(aws_server, secret_name))
        return secrets.get(token_name)
    
def assemble_sqlalchemy_uri() -> str:
    data = loads(get_aws_secret_raw('us-east-1', 'api/secrets/sql/database'))
    engine = data['engine']
    driver = data['driver']
    username = data['username']
    password = data['password']
    host = data['host']
    port = data['port']
    dbname = data['dbname']
    uri = f"{engine}+{driver}://{username}:{password}@{host}:{port}/{dbname}"
    return uri
    
from pydantic import BaseModel

LOGIN_PATH_URI = '/latest/user/login'
LOGIN_SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
LOGIN_DEFAULT_PBKDF2_ITERATIONS = 600000

CORS_ALLOWED_ORIGINS = get_aws_secret('us-east-2', 'api/secrets/cors', 'CORS_ALLOWED_ORIGINS')

GZIP_MINIMUM_SIZE = int(getenv('GZIP_MINIMUM_SIZE', 1000))

class CsrfSettings(BaseModel):
    secret_key:str = get_aws_secret('us-east-2', 'api/secrets/csrf/key', 'API_SECRET_CSRF_SECRET_KEY')
    