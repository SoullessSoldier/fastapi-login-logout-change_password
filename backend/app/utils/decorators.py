from functools import wraps

from jose import jwt

from db.models import TokenTable
from utils.utils import ALGORITHM, JWT_SECRET_KEY


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        payload = jwt.decode(kwargs['dependencies'], JWT_SECRET_KEY, ALGORITHM)
        user_id = payload['sub']
        data = kwargs['session'].query(TokenTable)\
            .filter_by(user_id=user_id, access_token=kwargs['dependencies'],
                       status=True).first()
        if data:
            return func(kwargs['dependencies'], kwargs['session'])
        else:
            return {'msg': 'Token blocked'}
    return wrapper
