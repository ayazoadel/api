# api/schemas.py — Modelos de request/response
from pydantic import BaseModel
from typing import Optional, List
from datetime import date


# ── AUTH ──────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    full_name: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    user_id:      int
    username:     str
    role:         str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str


# ── CATEGORÍAS ────────────────────────────────────────────────
class CategoriaCreate(BaseModel):
    nombre: str
    color:  str = "#8DD4F0"
    icono:  str = ""
    orden:  Optional[int] = None

class CategoriaUpdate(BaseModel):
    nombre: Optional[str] = None
    color:  Optional[str] = None
    icono:  Optional[str] = None
    orden:  Optional[int] = None

class CategoriaResponse(BaseModel):
    id:     int
    nombre: str
    color:  str
    icono:  str
    orden:  int


# ── CONTRASEÑAS ───────────────────────────────────────────────
class PasswordCreate(BaseModel):
    titulo:             str
    usuario:            str = ""
    password:           str           # en texto claro — API la encripta
    url:                str = ""
    notas:              str = ""
    categoria_id:       Optional[int] = None
    tiene_vencimiento:  bool = False
    dias_vencimiento:   Optional[int] = None
    inicio_vencimiento: Optional[date] = None

class PasswordUpdate(BaseModel):
    titulo:             Optional[str]  = None
    usuario:            Optional[str]  = None
    password:           Optional[str]  = None   # en texto claro
    url:                Optional[str]  = None
    notas:              Optional[str]  = None
    categoria_id:       Optional[int]  = None
    tiene_vencimiento:  Optional[bool] = None
    dias_vencimiento:   Optional[int]  = None
    inicio_vencimiento: Optional[date] = None

class PasswordResponse(BaseModel):
    id:                 int
    titulo:             str
    usuario:            str
    password:           str           # desencriptada
    url:                str
    notas:              str
    categoria_id:       Optional[int]
    tiene_vencimiento:  bool
    dias_vencimiento:   Optional[int]
    inicio_vencimiento: Optional[date]

class PasswordListItem(BaseModel):
    """Para el listado — sin la password desencriptada por seguridad."""
    id:                 int
    titulo:             str
    usuario:            str
    url:                str
    notas:              str
    categoria_id:       Optional[int]
    tiene_vencimiento:  bool
    dias_vencimiento:   Optional[int]
    inicio_vencimiento: Optional[date]


# ── ADMIN ─────────────────────────────────────────────────────
class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str
    status: str

class UpdateUserStatus(BaseModel):
    status: str   # active | pending | rejected

class UpdateUserRole(BaseModel):
    role: str     # admin | user

class AuditLogResponse(BaseModel):
    id:              int
    admin_username:  str
    target_username: Optional[str]
    action:          str
    old_value:       Optional[str]
    new_value:       Optional[str]
    created_at:      str


# ── GENERADOR ─────────────────────────────────────────────────
class GeneratePasswordRequest(BaseModel):
    length:       int  = 16
    uppercase:    bool = True
    lowercase:    bool = True
    numbers:      bool = True
    symbols:      bool = True
    exclude_ambiguous: bool = False
