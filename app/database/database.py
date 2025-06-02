from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base 

SQLALCHEMY_DATABASE_URL = 'mariadb+pymysql://root:kibana123@mariadb:3306/adusers'


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