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
import logging


router = APIRouter(
    prefix="/api/activate",
    tags=["Syncronize User"]
)

@router.put("/", status_code=status.HTTP_202_ACCEPTED) 
async def sync_user_from_ad_to_elastic_cluster(payload:schema.ActiveDirectoryUser, db: Session = Depends(get_db)): # type: ignore
    '''
    Sync AD user to ELK Cluster 
    '''

    try:
            # --- LDAP Authentication Placeholder ---
            # Here, you will authenticate the payload.username and payload.password against LDAP.
            # If authentication fails, raise HTTPException password or username is incorrect
            #
            # Example:
            # if not ldap_authenticate(payload.username, payload.password):
            #     raise HTTPException(status_code=401, detail="Invalid LDAP credentials")
            # --------------------------------------

            ad_auth = ActiveDirectoryAuth(bind_password='')
            success, message = ad_auth.authenticate_user(payload.username, payload.encrypted_hash)

            if success:

                logging.info(f'Active Directory Auth was Successfull: {message}')

                user = db.query(models.User).filter(models.User.username == payload.username).first()

                '''
                -------
                LOGIC 
                -------
                encrypt the password later
                '''

                es_user_payload = { # type: ignore
                    "password": payload.encrypted_hash,
                    "roles": [payload.es_roles],  # single role as a list
                    "full_name": payload.username,
                    "email": payload.email,
                    "enabled": True
                }

                if user:
                    # Update user info
                    user.email = payload.email # type: ignore
                    user.encrypted_hash = payload.encrypted_hash # type: ignore
                    user.updated_at = datetime.now(tz=timezone.utc) # type: ignore
                    user.status = schema.UserStatus.active.value # type: ignore
                    # Update user in Elasticsearch
                    try:
                        es.security.put_user( # type: ignore
                            username=payload.username,
                            body=es_user_payload # type: ignore
                        )
                    except ApiError as error:
                        raise HTTPException(status_code=500, detail=f"Failed to update user in Elasticsearch: {error}")
                else:
                    # Create new user  and activate user 
                    '''
                    only users from the ldap_sync service 
                    will get the pending_activateion status 
                    with default temp password 

                    create a new user because they are authenticated via ldap

                    '''
                    new_user = models.User(
                        username=payload.username,
                        email=payload.email,
                        es_roles='ad_sync',
                        encrypted_hash=payload.encrypted_hash,
                        status=schema.UserStatus.active.value,
                    )
                    db.add(new_user)
                    try:
                        es.security.put_user( # type: ignore
                            username=payload.username,
                            body=es_user_payload # type: ignore
                        )
                    except Exception as error:
                        raise HTTPException(status_code=500, detail=f"Failed to update user in Elasticsearch: {error}")
                db.commit()
                return {"message": f"User '{payload.username}' has been synchronized successfully."}
            else:
                raise HTTPException(status_code=401, detail=f"ActiveDirectory Authentication Failed: {message}")

    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(e)}"
        )
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(error)}"
        )