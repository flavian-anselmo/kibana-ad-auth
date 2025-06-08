from fastapi import APIRouter, Depends, status, HTTPException
from app.schema import schema
from app.database.database import get_db
from sqlalchemy.orm import Session
from app.models import models
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timezone
from app.elasticsearch.es import es
from elasticsearch8 import ApiError
from app.ldap.active_dir import ActiveDirectoryAuth
from app.security import sec
import logging


router = APIRouter(
    prefix="/api/activate",
    tags=["Syncronize User"]
)

@router.put("/", response_model=schema.UserActivationResponse, status_code=status.HTTP_202_ACCEPTED) 
async def sync_user_from_ad_to_elastic_cluster(payload:schema.ActiveDirectoryUser, db: Session = Depends(get_db)): # type: ignore
    '''
    Sync AD user to ELK Cluster 
    '''

    try:
            # --- LDAP Authentication Placeholder ---
            success = True
            message = 'Passed'

            # ad_auth = ActiveDirectoryAuth(config_file='settings.conf')
            # success, message = ad_auth.authenticate_user(payload.username, payload.encrypted_hash)

            if success:

                logging.info(f'Active Directory Auth was Successfull: {message}')

                user = db.query(models.User).filter(models.User.username == payload.username).first()

                # encrypt pswd            
                rsa_encrypted_hash:str = sec.encrypt_text(payload.encrypted_hash)

                es_user_payload = { 
                    "password": payload.encrypted_hash,
                    "roles": ['ad_sync'],  
                    "full_name": payload.username,
                    "email": f'{payload.username}@safaricom.co.ke',
                    "enabled": True
                }

                if user:
                    user.email = f'{payload.username}@safaricom.co.ke'
                    user.encrypted_hash = rsa_encrypted_hash
                    user.updated_at = datetime.now(tz=timezone.utc) 
                    user.status = schema.UserStatus.active.value 
                    try:
                        es.security.put_user( 
                            username=payload.username,
                            body=es_user_payload 
                        )
                    except ApiError as error:
                        raise HTTPException(status_code=500, detail=f"Failed to update user in Elasticsearch: {error}")
                else:
                    '''

                    create a new user and activate because they are authenticated via ldap

                    '''
                    new_user = models.User(
                        username=payload.username,
                        email=f'{payload.username}@safaricom.co.ke',
                        es_roles='ad_sync',
                        encrypted_hash=rsa_encrypted_hash,
                        status=schema.UserStatus.active.value,
                    )
                    db.add(new_user)
                    try:
                        es.security.put_user(
                            username=payload.username,
                            body=es_user_payload 
                        )
                    except Exception as error:
                        raise HTTPException(status_code=500, detail=f"Failed to update user in Elasticsearch: {error}")
                db.commit()
                return schema.UserActivationResponse(
                    message=f"User '{payload.username}' has been synchronized successfully"
                )
            else:
                raise HTTPException(status_code=401, detail=f"ActiveDirectory Authentication Failed: {message}")

    except SQLAlchemyError as error:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(error)}"
        )
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(error)}"
        )