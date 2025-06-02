from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
# from app.models.models import User # type: ignore
from app.database.database import Base, engine
from app.router import sync_user

# ensure tables are created
Base.metadata.create_all(bind=engine)

app:FastAPI = FastAPI(
    title= "Elastic AD AUTH & Sync",
    description="WorkAround for AD intergration to ELK",
    version="1.0.0",
    author='Service Availability Team'
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(sync_user.router)



@app.get("/")
def healthz():
    return {"message": f"ELK AD sync up & running"}