import json
import boto3
import uuid
from datetime import datetime
from decimal import Decimal

dynamodb = boto3.resource("dynamodb")

sensor_table = dynamodb.Table("sensor_data")
security_table = dynamodb.Table("security_logs")


def log_attack(attack_type, device_id, reason, severity="HIGH"):

    security_table.put_item(
        Item={
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "attack_type": attack_type,
            "device_id": device_id,
            "reason": reason,
            "severity": severity,
            "status": "BLOCKED"
        }
    )


def lambda_handler(event, context):

    print("ESP32 Data:", event)

    data = json.loads(json.dumps(event), parse_float=Decimal)

    timestamp = datetime.utcnow().isoformat()
    device_id = data.get("device_id")

    # -----------------------------
    # SECURITY CHECKS
    # -----------------------------

    if not data.get("signature"):
        log_attack(
            "SIGNATURE_ATTACK",
            device_id,
            "Missing or invalid digital signature"
        )

    if data.get("chain_valid") is False:
        log_attack(
            "BLOCKCHAIN_TAMPER",
            device_id,
            "Blockchain integrity failed"
        )

    temp = data.get("temperature")

    if temp is not None and float(temp) > 100:
        log_attack(
            "DATA_INJECTION",
            device_id,
            "Abnormal temperature value detected"
        )

    # -----------------------------
    # STORE SENSOR DATA
    # -----------------------------

    item = {
        "device_id": device_id,
        "received_at": timestamp,

        "temperature": data.get("temperature"),
        "pressure": data.get("pressure"),
        "altitude": data.get("altitude"),

        "mq2_raw": data.get("mq2_raw"),
        "mq2_percent": data.get("mq2_percent"),
        "mq2_alert": data.get("mq2_alert"),

        "payload_hash": data.get("payload_hash"),
        "signature": data.get("signature"),

        "chain_valid": data.get("chain_valid"),
        "chain_length": data.get("chain_length"),

        "algorithm": data.get("algorithm"),
        "encrypted": data.get("encrypted"),

        "block_index": data.get("blockchain_block", {}).get("index"),
        "block_hash": data.get("blockchain_block", {}).get("blockHash"),
        "previous_hash": data.get("blockchain_block", {}).get("previousHash")
    }

    sensor_table.put_item(Item=item)

    return {
        "statusCode": 200,
        "body": "Stored"
    }