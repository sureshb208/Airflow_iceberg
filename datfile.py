import os
import datetime
import pandas as pd
import boto3

# AWS S3 Configuration
S3_BUCKET_NAME = "your-s3-bucket"
BASE_DIR = "/path/to/count/files"  # Change this to your local directory

# Get today's date in YYYYMMDD format
today_str = datetime.datetime.today().strftime("%Y%m%d")

# Define today's folder path
today_folder = os.path.join(BASE_DIR, today_str)

# Define S3 Path: Store files under a folder with today's date
S3_OUTPUT_PATH = f"parquet-output/{today_str}/count_data.parquet"

# Initialize S3 client
s3 = boto3.client("s3")

def check_s3_file_exists(bucket_name, s3_path):
    """Check if the file already exists in S3."""
    try:
        s3.head_object(Bucket=bucket_name, Key=s3_path)
        print(f"ℹ️ File already exists: s3://{bucket_name}/{s3_path}")
        return True  # File exists
    except s3.exceptions.ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False  # File does not exist
        else:
            print(f"⚠️ Error checking S3 file: {e}")
            return False

def delete_existing_s3_file(bucket_name, s3_path):
    """Delete the existing Parquet file in S3 if it exists."""
    if check_s3_file_exists(bucket_name, s3_path):
        s3.delete_object(Bucket=bucket_name, Key=s3_path)
        print(f"🗑️ Deleted existing file: s3://{bucket_name}/{s3_path}")

def process_count_files(directory, date_str):
    """Process only *_ok* files and extract filename, count, and date."""
    data = []  

    if not os.path.exists(directory):
        print(f"⚠️ Directory not found: {directory}")
        return data

    for filename in os.listdir(directory):
        if "_ok" not in filename:
            continue
        
        file_path = os.path.join(directory, filename)

        if not os.path.isfile(file_path):
            continue

        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if "~" in line:
                    file_name, count = line.split("~")
                    data.append({"file_name": file_name, "count": int(count), "date": date_str})

    return data

def write_to_parquet(data, output_file):
    """Write extracted data to a Parquet file using Pandas + fastparquet."""
    df = pd.DataFrame(data)
    df.to_parquet(output_file, engine="fastparquet", index=False)

def upload_to_s3(local_file, bucket_name, s3_path):
    """Upload a file to S3."""
    s3.upload_file(local_file, bucket_name, s3_path)
    print(f"✅ File uploaded to S3: s3://{bucket_name}/{s3_path}")

# Process today's *ok* files
data = process_count_files(today_folder, today_str)

# If data is available, check and delete only if running multiple times
if data:
    if check_s3_file_exists(S3_BUCKET_NAME, S3_OUTPUT_PATH):
        delete_existing_s3_file(S3_BUCKET_NAME, S3_OUTPUT_PATH)

    # Write new Parquet file
    parquet_file = "count_data.parquet"
    write_to_parquet(data, parquet_file)

    # Upload new Parquet file to S3
    upload_to_s3(parquet_file, S3_BUCKET_NAME, S3_OUTPUT_PATH)

    print("✅ Processing complete.")
else:
    print("⚠️ No valid *ok* count files found for today.")