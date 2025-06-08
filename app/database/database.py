from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base 
from app.config import env


SQLALCHEMY_DATABASE_URL = env.SQLALCHEMY_DATABASE_URL


engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=True,  # Show SQL queries
    pool_pre_ping=True,
    connect_args={"connect_timeout": 30}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    '''
    database dependancy for any endpont making a query to the db 
    
    '''
    db = SessionLocal()
    try:
        yield db 

    finally:
        db.close()