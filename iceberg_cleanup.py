from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from datetime import datetime
import logging
import json
import boto3

from pyspark.sql import SparkSession

# Initialize Spark session with Iceberg
spark = SparkSession.builder \
    .appName('IcebergMaintenance') \
    .config('spark.sql.catalog.spark_catalog', 'org.apache.iceberg.spark.SparkCatalog') \
    .config('spark.sql.catalog.spark_catalog.warehouse', 's3://your-iceberg-warehouse/') \
    .config('spark.sql.catalog.spark_catalog.catalog-impl', 'org.apache.iceberg.aws.glue.GlueCatalog') \
    .config('spark.sql.catalog.spark_catalog.io-impl', 'org.apache.iceberg.aws.s3.S3FileIO') \
    .config('spark.sql.catalog.spark_catalog.lock-impl', 'org.apache.iceberg.aws.glue.DynamoLockManager') \
    .config('spark.sql.catalog.spark_catalog.lock.table', 'iceberg_lock_table') \
    .getOrCreate()

# Read configuration file for table list
CONFIG_FILE = '/path/to/config.json'
SNS_TOPIC_ARN = 'arn:aws:sns:us-west-2:123456789012:YourSNSTopic'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize SNS client
sns_client = boto3.client('sns')

# Load configuration file
def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config.get('tables', [])
    except Exception as e:
        logging.error(f'Failed to load config file: {e}')
        raise

# Send SNS notification
def send_sns_notification(subject, message):
    try:
        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        logging.info('SNS notification sent successfully')
    except Exception as e:
        logging.error(f'Failed to send SNS notification: {e}')

# Maintenance tasks
def expire_snapshots(**kwargs):
    tables = load_config()
    for table in tables:
        try:
            logging.info(f"Starting snapshot expiration for {table}")
            spark.sql(f'''
                CALL spark_catalog.{table}.expire_snapshots(
                    older_than => TIMESTAMP '2023-01-01T00:00:00',
                    retain_last => 5
                )
            ''')
            logging.info(f"Snapshot expiration completed for {table}")
            send_sns_notification(
                f'Snapshot Expiration Success: {table}',
                f'Snapshot expiration completed successfully for {table}'
            )
        except Exception as e:
            logging.error(f"Error during snapshot expiration for {table}: {e}")
            send_sns_notification(
                f'Snapshot Expiration Failed: {table}',
                f'Error during snapshot expiration for {table}: {e}'
            )
            raise


def remove_orphan_files(**kwargs):
    tables = load_config()
    for table in tables:
        try:
            logging.info(f"Starting orphan file removal for {table}")
            spark.sql(f'''
                CALL spark_catalog.{table}.remove_orphan_files(
                    older_than => TIMESTAMP '2023-01-01T00:00:00'
                )
            ''')
            logging.info(f"Orphan file removal completed for {table}")
            send_sns_notification(
                f'Orphan File Removal Success: {table}',
                f'Orphan file removal completed successfully for {table}'
            )
        except Exception as e:
            logging.error(f"Error during orphan file removal for {table}: {e}")
            send_sns_notification(
                f'Orphan File Removal Failed: {table}',
                f'Error during orphan file removal for {table}: {e}'
            )
            raise

# Define Airflow DAG
default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'retries': 1,
}

dag = DAG(
    'iceberg_maintenance_dag',
    default_args=default_args,
    description='DAG for Iceberg metadata cleanup with dynamic table list',
    schedule_interval='@weekly',
    start_date=days_ago(1),
    catchup=False,
)

expire_snapshots_task = PythonOperator(
    task_id='expire_snapshots',
    python_callable=expire_snapshots,
    provide_context=True,
    dag=dag
)

remove_orphan_files_task = PythonOperator(
    task_id='remove_orphan_files',
    python_callable=remove_orphan_files,
    provide_context=True,
    dag=dag
)

expire_snapshots_task >> remove_orphan_files_task
