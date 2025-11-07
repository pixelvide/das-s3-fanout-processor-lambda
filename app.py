# This Lambda function reads the Kinesis Firehose records as Input, decrypt the log records using KMS key, unzip the records and then categories the event type into S3 folder structure.
from __future__ import print_function
import os
import json
import boto3
from botocore.exceptions import ClientError
import base64
import zlib
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType
import datetime
import pyarrow as pa
import pyarrow.json as pa_json
import pyarrow.parquet as pa_parquet

enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
kms = boto3.client('kms', region_name=os.environ['DAS_KMS_REGION_NAME'])
s3 = boto3.client('s3')
today_date = datetime.datetime.now()

enc_keys = {}


class MyRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "BC"

    def __new__(cls, *args, **kwargs):
        obj = super(RawMasterKeyProvider, cls).__new__(cls)
        return obj

    def __init__(self, plain_key):
        RawMasterKeyProvider.__init__(self)
        self.wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                                        wrapping_key=plain_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC)

    def _get_raw_key(self, key_id):
        return self.wrapping_key


def decrypt_payload(payload, data_key):
    my_key_provider = MyRawMasterKeyProvider(data_key)
    my_key_provider.add_master_key("DataKey")
    # Decrypt the records using the master key.
    decrypted_plaintext, header = enc_client.decrypt(
        source=payload,
        materials_manager=aws_encryption_sdk.materials_managers.default.DefaultCryptoMaterialsManager(
            master_key_provider=my_key_provider))
    return decrypted_plaintext


def decrypt_decompress(payload, key):
    decrypted = decrypt_payload(payload, key)
    # Decompress the records using zlib library.
    decrypted = zlib.decompress(decrypted, zlib.MAX_WBITS + 16)
    return decrypted


def decrypt_kms_data_key(data_key):
    if data_key not in enc_keys[os.environ['DAS_RDS_RESOURCE_ID']]:
        enc_keys[os.environ['DAS_RDS_RESOURCE_ID']][data_key] = kms.decrypt(CiphertextBlob=data_key,
                                                                            EncryptionContext={
                                                                                'aws:rds:dbc-id': os.environ[
                                                                                    'DAS_RDS_RESOURCE_ID']})

    return enc_keys[os.environ['DAS_RDS_RESOURCE_ID']][data_key]

def get_s3_object(bucket, key):
    try:
        return s3.get_object(Bucket=bucket, Key=key)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            print(f"Warning: S3 object {key} not found in {bucket}. Returning None.")
            return None
        else:
            raise

# Lambda Handler entry point
def handler(event, context):
    filter_file_path = 'filters/{0}.json'.format(os.environ.get('DAS_FILTER_NAME', 'default'))
    if not os.path.exists(filter_file_path):
        filter_file_path = 'filters/default.json'

    with open(filter_file_path, 'r') as filter_file:
        filters = json.load(filter_file)

    if os.environ['DAS_RDS_RESOURCE_ID'] not in enc_keys:
        enc_keys[os.environ['DAS_RDS_RESOURCE_ID']] = {}

    # Loop over SQS events
    for sqs_record in event['Records']:
        # Parse and Loop over S3 events
        s3_event = json.loads(sqs_record['body'])

        if 'Records' not in s3_event:
            continue

        for s3_record in s3_event['Records']:
            print("Received S3 record")
            print("Bucket: " + s3_record["s3"]["bucket"]["name"])
            print("Object: " + s3_record["s3"]["object"]["key"])

            response = get_s3_object(s3_record["s3"]["bucket"]["name"], s3_record["s3"]["object"]["key"])
            if not response:
                continue

            # Parse s3 file and loop over das events saved in s3 file
            das_records = response['Body'].read().decode('utf-8')
            das_records = json.loads("[{}]".format(das_records.replace('}{', '},{')))

            das_processed_records = []
            for das_record in das_records:
                das_processed_records = das_processed_records + process_das_record(das_record, filters)

            file_path = s3_record["s3"]["object"]["key"].split("/")
            file_path[0] = "das"
            file_path[1] = os.environ['DAS_FILTER_NAME']

            tmp_path = "/tmp/" + file_path[-1]
            f = open(tmp_path, "w")
            f.write("\n".join(das_processed_records))
            f.close()

            pa_table_schema = pa.schema([
                pa.field('logTime', pa.string()),
                pa.field('statementId', pa.int64()),
                pa.field('substatementId', pa.int64()),
                pa.field('objectType', pa.string()),
                pa.field('command', pa.string()),
                pa.field('objectName', pa.string()),
                pa.field('databaseName', pa.string()),
                pa.field('dbUserName', pa.string()),
                pa.field('remoteHost', pa.string()),
                pa.field('sessionId', pa.string()),
                pa.field('rowCount', pa.int64()),
                pa.field('commandText', pa.string()),
                pa.field('paramList', pa.list_(pa.string())),
                pa.field('pid', pa.int64()),
                pa.field('clientApplication', pa.string()),
                pa.field('exitCode', pa.string()),
                pa.field('class', pa.string()),
                pa.field('serverHost', pa.string()),
                pa.field('type', pa.string()),
                pa.field('startTime', pa.string()),
                pa.field('errorMessage', pa.string()),
            ])
            table = pa_json.read_json(tmp_path, parse_options=pa_json.ParseOptions(explicit_schema=pa_table_schema))
            writer = pa.BufferOutputStream()
            pa_parquet.write_table(table, writer, compression='snappy')

            s3.put_object(
                Bucket=s3_record["s3"]["bucket"]["name"],
                Key="/".join(file_path),
                Body=bytes(writer.getvalue())
            )

            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    return event


def process_das_record(record, filters):
    if record['type'] == 'DatabaseActivityMonitoringRecords':
        db_events = record["databaseActivityEvents"]
        data_key = base64.b64decode(record["key"])
        try:
            # Decrypt the envelope master key using KMS
            data_key_decrypt_result = decrypt_kms_data_key(data_key)
        except Exception as e:
            print(e)
            raise e

        try:
            plaintext_events = decrypt_decompress(base64.b64decode(db_events), data_key_decrypt_result['Plaintext'])
        except Exception as e:
            print(e)
            raise e

        ret_obj = []
        # parse through all activity and categorize it.
        try:
            events = json.loads(plaintext_events)
            for db_event in events['databaseActivityEventList']:
                # filter out events which you don't want to log.
                if db_event['type'] == "heartbeat":
                    continue

                db_event['exitCode'] = str(db_event['exitCode'])

                if filter_das_record(db_event, filters.get('query', {})):
                    for d in filters.get('drop', []):
                        db_event.pop(d, None)

                    ret_obj.append(json.dumps(db_event))
        except Exception as e:
            print(db_event)
            print(e)
            raise e

        if len(ret_obj):
            return [
                "\n".join(ret_obj)
            ]

        return []


def filter_das_record(record, query):
    if "type" in query:
        if query['type'] == "not":
            return not filter_das_record(record, query['field'])
        elif query['type'] == "dimensionExists":
            if query['dimension'] in record:
                return True
        elif query['type'] == "selector":
            if record[query['dimension']] == query['value']:
                return True
        elif query['type'] == "and":
            for field in query['fields']:
                if not filter_das_record(record, field):
                    return False
            return True
        elif query['type'] == "or":
            for field in query['fields']:
                if filter_das_record(record, field):
                    return True
        elif query['type'] == "contains":
            value = record[query['dimension']]
            if (type(value) is list or type(value) is dict or type(value) is str) and query['value'] in value:
                return True
        return False
    return True
