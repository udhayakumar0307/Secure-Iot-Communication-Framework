import json
import boto3
from decimal import Decimal

dynamodb = boto3.resource('dynamodb', region_name='ap-south-1')

sensor_table = dynamodb.Table('sensor_data')
security_table = dynamodb.Table('security_logs')


class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def lambda_handler(event, context):

    try:

        # -------- SENSOR DATA --------
        sensor_response = sensor_table.scan(Limit=100)
        sensor_items = sensor_response.get("Items", [])

        for item in sensor_items:
            item["blockchain_auth"] = item.get("chain_valid", False)
            item["signature_verified"] = True if item.get("signature") else False

        # -------- SECURITY LOGS --------
        security_response = security_table.scan(Limit=50)
        security_items = security_response.get("Items", [])

        return {
            "statusCode": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "success": True,
                "sensor_count": len(sensor_items),
                "security_count": len(security_items),
                "data": sensor_items,
                "security_logs": security_items
            }, cls=DecimalEncoder)
        }

    except Exception as e:

        return {
            "statusCode": 500,
            "headers": {
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({
                "success": False,
                "error": str(e)
            })
        }