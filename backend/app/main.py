from datetime import datetime, timezone
from db import schemas, models
from db.models import User, TokenTable
from db.database import Base, engine, SessionLocal
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import jwt

from utils.auth_bearer import jwt_bearer
from utils.utils import get_hashed_password, verify_password, \
    create_access_token, create_refresh_token, JWT_SECRET_KEY, ALGORITHM

Base.metadata.create_all(engine)


def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


app = FastAPI()


@app.post("/register")
def register_user(user: schemas.UserCreate,
                  session: Session = Depends(get_session)):
    existing_user = session.query(models.User).\
        filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail='Email already registered')
    encrypted_password = get_hashed_password(user.password)

    new_user = models.User(username=user.username, email=user.email,
                           password=encrypted_password)

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {'message': 'user created successfully'}


@app.post('/login', response_model=schemas.TokenSchema)
def login(request: schemas.RequestDetails, db: Session = Depends(get_session)):
    user = db.query(User).filter(User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect email')
    hashed_pass = user.password
    if not verify_password(request.password, hashed_pass):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Incorrect password')

    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)

    token_db = models.TokenTable(user_id=user.id, access_token=access_token,
                                 refresh_token=refresh_token, status=True)
    db.add(token_db)
    db.commit()
    db.refresh(token_db)
    return {'access_token': access_token, 'refresh_token': refresh_token}


@app.get('/get_users')
def get_users(dependencies=Depends(jwt_bearer),
             session: Session = Depends(get_session)):
    users = session.query(models.User).all()
    return users


@app.post('/change_password')
def change_password(request: schemas.ChangePassword,
                    db: Session = Depends(get_session)):
    user = db.query(User).filter(User.email == request.email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='User not found')
    if not verify_password(request.old_password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail='Invalid old password')
    encrypted_password = get_hashed_password(request.new_password)
    user.password = encrypted_password
    db.commit()
    return {'message': 'Password changed successfully'}


@app.post('/logout')
def logout(dependencies=Depends(jwt_bearer),
           db: Session = Depends(get_session)):
    token = dependencies
    payload = jwt.decode(token, JWT_SECRET_KEY, ALGORITHM)
    user_id = payload['sub']
    token_records = db.query(TokenTable).all()
    info = []
    for record in token_records:
        print('record')
        if (datetime.now(timezone.utc) - record.created_date).days > 1:
            info.append(record.user_id)
    if info:
        existing_token = db.query(TokenTable)\
            .where(TokenTable.user_id.in_(info)).delete()
        db.commit()
    existing_token = db.query(TokenTable)\
        .filter(TokenTable.user_id == user_id,
                TokenTable.access_token == token).first()
    if existing_token:
        existing_token.status = False
        db.add(existing_token)
        db.commit()
        db.refresh(existing_token)
    return {'message': 'Logout successfully'}



