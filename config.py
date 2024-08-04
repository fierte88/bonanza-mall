import os

class Config:
    SECRET_KEY = 'nous516024'
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")or 'postgresql://postgres.jmiotireachftycaknlh:Marti%4012345nous@aws-0-eu-central-1.pooler.supabase.com:6543/postgres'
    SQLALCHEMY_TRACK_MODIFICATIONS = False