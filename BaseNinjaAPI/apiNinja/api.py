from typing import Any
from django.http import HttpRequest
from ninja import NinjaAPI, Schema
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from ninja.security import HttpBearer
from jwt import encode, decode as jwt_decode, exceptions
from django.conf import settings
from pydantic import BaseModel
from .models import *
from django.shortcuts import get_object_or_404
from datetime import datetime, timedelta
from django.db import IntegrityError
from typing import Optional

api = NinjaAPI()

class AuthBearer(HttpBearer):
    def authenticate(self, request, token):
        if BlacklistedToken.objects.filter(token=token).exists():
            return None
        
        try:
            decoded_data = jwt_decode(token, settings.SECRET_KEY, algorithms=['HS256'])

            return User.objects.get(id=decoded_data['user_id'])
        except (exceptions.DecodeError, User.DoesNotExist):
            return None

auth = AuthBearer()

class RegisterSchema(BaseModel):
    username: str
    email: str
    password: str

@api.post("/register")
def register(request, data: RegisterSchema):
    if User.objects.filter(username=data.username).exists():
        return {"status": False, "message": "Username already taken", "data": None}
    
    if User.objects.filter(email=data.email).exists():
        return {"status": False, "message": "Email already in use", "data": None}
    
    user = User(
        username=data.username,
        email=data.email,
        password=make_password(data.password),
    )

    user.save()

    return {
        "status": True,
        "message": "success Get data",
        "data": {
            "username": user.username,
            "email": user.email,
        }
    }

class LoginSchema(Schema):
    username: str
    password: str

@api.post("/login")
def login(request, payload: LoginSchema):
    try:
        username = payload.username
        password = payload.password

        user = User.objects.get(username=username)

        if not user.check_password(password):
            return {"status": False, "message": "Wrong Password", "data": None}
        
        # Set expiration time (1 hour from now)
        expiration = datetime.utcnow() + timedelta(hours=1)
        token = encode({
            'user_id': user.id,
            'exp': expiration
        }, settings.SECRET_KEY, algorithm='HS256')

        return {
            "status": True,
            "message": "success Get data",
            "data": {
                "username": user.username,
                "email": user.email,
                "token": token
            }
        }
    except User.DoesNotExist:
        return {"status": False, "message": "Wrong Username or Password", "data": None}

@api.post("/logout", auth=auth)
def logout(request):
    token = request.headers.get("Authorization").split(" ")[1]
    BlacklistedToken.objects.create(token=token)
    
    return {"message": "Successfully logged out"}

@api.get("/protected", auth=auth)
def protected(request):
    return {"message": "This is a protected endpoint"}

class ParentSchema(Schema):
    name: str
    number_parent_a: int
    number_parent_b: int
    result_parent: Optional[float] = None

@api.get("/parent", auth=auth)
def get(request):
    data = Parent.objects.all()
    
    if not data:
        return {
            "status": False,
            "message": "No data found",
            "data": []
        }
    
    return {
            "status": True,
            "message": "Success get data",
            "data": [ 
                {
                    "id": d.id,
                    "name": d.name,
                    "number_a": d.number_parent_a,
                    "number_b": d.number_parent_b,
                    "result": d.result_parent,
                }
                for d in data
            ]
    }

@api.post("/parent", auth=auth)
def create(request, data: ParentSchema):
    try:
        # Perhitungan
        plus = data.number_parent_a + data.number_parent_b
        minus = data.number_parent_a - data.number_parent_b
        divide = data.number_parent_a / data.number_parent_b
        multiplication = data.number_parent_a * data.number_parent_b

        # Hasil total
        result = plus + minus + divide + multiplication

        # Membuat objek Parent dengan hasil perhitungan
        d = Parent.objects.create(
            name=data.name,
            number_parent_a=data.number_parent_a,
            number_parent_b=data.number_parent_b,
            result_parent=result
        )

        # Mengembalikan respons sukses
        return {
            "status": True,
            "message": "Data created successfully",
            "data": {
                "id": d.id,
                "name": d.name,
                "number_a": d.number_parent_a,
                "number_b": d.number_parent_b,
                "result": {
                    "+": plus,
                    "-": minus,
                    "/": divide,
                    "*": multiplication,
                    "result_all_plus": result
                },
            }
        }
    except IntegrityError as e:
        return {
            "status": False,
            "message": "Failed to create data - Integrity error",
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": False,
            "message": "Failed to create data",
            "error": str(e)
        }

@api.get("/parent/{id}", auth=auth)
def get(request, id:int):
    data = get_object_or_404(Parent, id=id)
    
    if not data:
        return {
            "status": False,
            "message": "No data found",
            "data": []
        }
    
    return [
        {
            "status": True,
            "message": "Success get data",
            "data": {
                "id": data.id,
                "name": data.name,
                "number_a": data.number_parent_a,
                "number_b": data.number_parent_b,
                "result": data.result_parent,
            }
        }
    ]

@api.put("/parent/{id}", auth=auth)
def update(request, id: int, data: ParentSchema):
    try:
        d = get_object_or_404(Parent, id=id)

        # Perhitungan
        plus = data.number_parent_a + data.number_parent_b
        minus = data.number_parent_a - data.number_parent_b
        divide = data.number_parent_a / data.number_parent_b
        multiplication = data.number_parent_a * data.number_parent_b

        # Hasil total
        result = plus + minus + divide + multiplication

        # Membuat objek Parent dengan hasil perhitungan
        d.name=data.name
        d.number_parent_a=data.number_parent_a
        d.number_parent_b=data.number_parent_b
        d.result_parent=result
        
        d.save()

        # Mengembalikan respons sukses
        return {
            "status": True,
            "message": "Data created successfully",
            "data": {
                "id": d.id,
                "name": d.name,
                "number_a": d.number_parent_a,
                "number_b": d.number_parent_b,
                "result": {
                    "+": plus,
                    "-": minus,
                    "/": divide,
                    "*": multiplication,
                    "result_all_plus": result
                },
            }
        }
    except IntegrityError as e:
        return {
            "status": False,
            "message": "Failed to create data - Integrity error",
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": False,
            "message": "Failed to create data",
            "error": str(e)
        }

@api.delete("/parent/{id}", auth=auth)
def delete(request, id: int):
    try:
        data = get_object_or_404(Parent, id=id)
        data.delete()
        return {
            "status": True,
            "message": "Deleted successfully"
        }
    except IntegrityError as e:
        return {
            "status": False,
            "message": "Failed to delete - Integrity error",
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": False,
            "message": "Failed to delete",
            "error": str(e)
        }

class ChildSchema(Schema):
    name:str
    parent_id:int
    number_child_a:int
    number_child_b:int
    result_child:Optional[float] = None
    result_child_parent:Optional[float] = None

@api.get("/child", auth=auth)
def get(request):
    data = Child.objects.all()
    
    if not data:
        return {
            "status": False,
            "message": "No data found",
            "data": []
        }
    
    return {
        "status": True,
        "message": "Success get data",
        "data": [
            {
                "id": d.id,
                "name": d.name,
                "number_a": d.number_child_a,
                "number_b": d.number_child_b,
                "result_child": d.result_child,
                "result_child_parent": d.result_child_parent,
            }
            for d in data
        ]
    }
@api.post("/child", auth=auth)
def create(request, data: ChildSchema):
    try:
        # Perhitungan
        plus = data.number_child_a + data.number_child_b
        minus = data.number_child_a - data.number_child_b
        divide = data.number_child_a / data.number_child_b
        multiplication = data.number_child_a * data.number_child_b

        # Hasil total
        result_child = plus + minus + divide + multiplication

        # Get Parent
        try:
            parent = Parent.objects.get(id=data.parent_id)
        except Parent.DoesNotExist:
            return {"status": False, "message": "Parent Not Found"}

        result_child_parent = parent.result_parent + result_child

        # Membuat objek Child dengan hasil perhitungan
        d = Child.objects.create(
            name=data.name,
            parent_id=parent,
            number_child_a=data.number_child_a,
            number_child_b=data.number_child_b,
            result_child=result_child,
            result_child_parent=result_child_parent
        )

        # Mengembalikan respons sukses
        return {
            "status": True,
            "message": "Data created successfully",
            "data": {
                "id": d.id,
                "name": d.name,
                "number_a": d.number_child_a,
                "number_b": d.number_child_b,
                "result": {
                    "+": plus,
                    "-": minus,
                    "/": divide,
                    "*": multiplication,
                    "result_all_plus": result_child,
                    "result_parent_plus_child": result_child_parent,
                },
            }
        }
    except IntegrityError as e:
        return {
            "status": False,
            "message": "Failed to create data - Integrity error",
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": False,
            "message": "Failed to create data",
            "error": str(e)
        }

@api.get("/child/{id}", auth=auth)
def get(request, id:int):
    data = get_object_or_404(Child, id=id)
    
    if not data:
        return {
            "status": False,
            "message": "No data found",
            "data": []
        }
    
    return [
        {
            "status": True,
            "message": "Success get data",
            "data": {
                "id": data.id,
                "name": data.name,
                "parent": data.parent_id.name,
                "number_a": data.number_child_a,
                "number_b": data.number_child_b,
                "result_child": data.result_child,
                "result_parent_child": data.result_child_parent,
            }
        }
    ]

@api.put("/child/{id}", auth=auth)
def update(request, id: int, data: ChildSchema):
    try:
        d = get_object_or_404(Child, id=id)

        # Perhitungan
        plus = data.number_child_a + data.number_child_b
        minus = data.number_child_a - data.number_child_b
        divide = data.number_child_a / data.number_child_b
        multiplication = data.number_child_a * data.number_child_b

        # Hasil total
        result_child = plus + minus + divide + multiplication

        try:
            parent = Parent.objects.get(id=data.parent_id)
        except Parent.DoesNotExist:
            return {"status": False, "message": "Parent Not Found"}

        result_child_parent = parent.result_parent + result_child
        
        # Membuat objek Parent dengan hasil perhitungan
        d.name=data.name
        d.parent_id = parent
        d.number_child_a=data.number_child_a
        d.number_child_b=data.number_child_b
        d.result_child=result_child
        d.result_child_parent=result_child_parent
        
        d.save()

        # Mengembalikan respons sukses
        return {
            "status": True,
            "message": "Data created successfully",
            "data": {
                "id": d.id,
                "name": d.name,
                "number_a": d.number_child_a,
                "number_b": d.number_child_b,
                "result": {
                    "+": plus,
                    "-": minus,
                    "/": divide,
                    "*": multiplication,
                    "result_all_plus": result_child,
                    "result_parent_plus_child": result_child_parent,
                },
            }
        }
    except IntegrityError as e:
        return {
            "status": False,
            "message": "Failed to create data - Integrity error",
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": False,
            "message": "Failed to create data",
            "error": str(e)
        }

@api.delete("/child/{id}", auth=auth)
def delete(request, id: int):
    try:
        data = get_object_or_404(Child, id=id)
        data.delete()
        return {
            "status": True,
            "message": "Deleted successfully"
        }
    except IntegrityError as e:
        return {
            "status": False,
            "message": "Failed to delete - Integrity error",
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": False,
            "message": "Failed to delete",
            "error": str(e)
        }
