import json
import logging
import requests
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Airflow API endpoint
AIRFLOW_API_URL = "http://<AIRFLOW_HOST>:8080/api/v1/dags/{dag_id}/dagRuns"
AIRFLOW_USERNAME = "your_airflow_username"
AIRFLOW_PASSWORD = "your_airflow_password"

def trigger_airflow_dag(dag_id, run_id, conf):
    """
    Triggers an Airflow DAG via the REST API.
    """
    url = AIRFLOW_API_URL.format(dag_id=dag_id)
    headers = {"Content-Type": "application/json"}
    payload = {
        "dag_run_id": run_id,
        "conf": conf
    }

    try:
        response = requests.post(
            url,
            headers=headers,
            auth=(AIRFLOW_USERNAME, AIRFLOW_PASSWORD),
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        logger.info(f"Successfully triggered DAG {dag_id} with run ID {run_id}.")
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to trigger Airflow DAG: {e}")
        raise

def send_sns_notification(topic_arn, subject, message):
    """
    Send an SNS notification with the provided subject and message.
    """
    sns_client = boto3.client('sns')
    try:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message
        )
        logger.info(f"SNS notification sent: {subject}")
    except (BotoCoreError, ClientError) as e:
        logger.error(f"Failed to send SNS notification: {e}")
        raise

def lambda_handler(event, context):
    """
    AWS Lambda function to handle SNS messages and trigger an Airflow DAG.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        for record in event['Records']:
            if record['EventSource'] == 'aws:sns':
                sns_message = json.loads(record['Sns']['Message'])
                
                dag_id = sns_message.get('dag_id', 'default_dag_id')
                run_id = sns_message.get('run_id', f"manual_{int(time.time())}")
                conf = sns_message.get('conf', {})
                
                # Trigger the Airflow DAG
                trigger_airflow_dag(dag_id, run_id, conf)

                # Send notification on success
                sns_topic_arn = "arn:aws:sns:REGION:ACCOUNT_ID:TOPIC_NAME"
                send_sns_notification(
                    sns_topic_arn,
                    f"Airflow DAG {dag_id} Triggered",
                    f"Successfully triggered DAG {dag_id} with run ID {run_id}"
                )
                
    except Exception as e:
        logger.error(f"Error processing event: {e}")
        raise