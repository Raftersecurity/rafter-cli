# Cloud integration — INTENTIONAL FAKE SECRETS for fixture testing
import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7TEXAMPLE"
AWS_SECRET_KEY = "aws_secret='wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY1ab'"

# Database connection with embedded credentials
DB_URL = "postgres://deploy_user:p4ssw0rd_n0t_r34l@db.fixture.internal:5432/appdata"

# API call with bearer token
AUTH_HEADER = "Bearer eyAbCdEf0123456789xyzABCDEF.ghijklmnop0123456789"

def get_db_connection():
    return DB_URL
