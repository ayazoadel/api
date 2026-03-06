# api/main.py — FastAPI app principal
import random
import string
from datetime import date
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware

from config   import settings
from db       import DBConn
from crypto   import (encrypt_password, decrypt_password,
                      hash_password, verify_password, generate_salt)
from auth     import create_token, get_current_user, require_admin
from schemas  import (
    LoginRequest, RegisterRequest, TokenResponse, ChangePasswordRequest,
    CategoriaCreate, CategoriaUpdate, CategoriaResponse,
    PasswordCreate, PasswordUpdate, PasswordResponse, PasswordListItem,
    UserResponse, UpdateUserStatus, UpdateUserRole, AuditLogResponse,
    GeneratePasswordRequest,
)

app = FastAPI(
    title="Gestor de Contraseñas API",
    version="1.0.0",
    description="API REST para la app mobile del gestor de contraseñas",
)

# CORS — permite que React Native llame a la API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ════════════════════════════════════════════════════════════
#  AUTH
# ════════════════════════════════════════════════════════════

@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(body: LoginRequest):
    """Login — retorna JWT token."""
    with DBConn() as (cur, conn):
        cur.execute(
            "SELECT id, username, password_hash, salt, role, status "
            "FROM users WHERE username = %s",
            (body.username,)
        )
        user = cur.fetchone()

    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    if user["status"] == "pending":
        raise HTTPException(status_code=403, detail="Cuenta pendiente de aprobación")
    if user["status"] == "rejected":
        raise HTTPException(status_code=403, detail="Cuenta rechazada")

    token = create_token(user["id"], user["username"], user["role"])
    return TokenResponse(
        access_token=token,
        user_id=user["id"],
        username=user["username"],
        role=user["role"],
    )


@app.post("/auth/register", status_code=201, tags=["Auth"])
def register(body: RegisterRequest):
    """Solicitud de nuevo usuario — queda en estado 'pending'."""
    if len(body.username) < 3:
        raise HTTPException(status_code=400, detail="Usuario debe tener al menos 3 caracteres")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Contraseña debe tener al menos 6 caracteres")

    with DBConn() as (cur, conn):
        cur.execute("SELECT id FROM users WHERE username = %s", (body.username,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="El usuario ya existe")

        hashed = hash_password(body.password)
        salt   = generate_salt()
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, role, status) "
            "VALUES (%s, %s, %s, 'user', 'pending')",
            (body.username, hashed, salt)
        )
        conn.commit()

    return {"message": "Solicitud enviada. Un administrador revisará tu cuenta."}


@app.post("/auth/change-password", tags=["Auth"])
def change_password(
    body: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user)
):
    """Cambiar contraseña del usuario logueado."""
    user_id = int(current_user["sub"])

    with DBConn() as (cur, conn):
        cur.execute(
            "SELECT password_hash, salt FROM users WHERE id = %s", (user_id,)
        )
        user = cur.fetchone()
        if not user or not verify_password(body.current_password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Contraseña actual incorrecta")

        # Re-encriptar todas las contraseñas con la nueva master password
        cur.execute(
            "SELECT id, encrypted_password FROM passwords WHERE user_id = %s",
            (user_id,)
        )
        passwords = cur.fetchall()

        old_salt = user["salt"]
        new_salt = generate_salt()
        new_hash = hash_password(body.new_password)

        for p in passwords:
            try:
                plain     = decrypt_password(p["encrypted_password"], body.current_password, old_salt)
                encrypted = encrypt_password(plain, body.new_password, new_salt)
                cur.execute(
                    "UPDATE passwords SET encrypted_password = %s WHERE id = %s",
                    (encrypted, p["id"])
                )
            except Exception:
                pass

        cur.execute(
            "UPDATE users SET password_hash = %s, salt = %s WHERE id = %s",
            (new_hash, new_salt, user_id)
        )
        conn.commit()

    return {"message": "Contraseña actualizada correctamente"}


@app.get("/auth/me", response_model=UserResponse, tags=["Auth"])
def get_me(current_user: dict = Depends(get_current_user)):
    """Datos del usuario logueado."""
    user_id = int(current_user["sub"])
    with DBConn() as (cur, _):
        cur.execute(
            "SELECT id, username, role, status FROM users WHERE id = %s", (user_id,)
        )
        user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user


# ════════════════════════════════════════════════════════════
#  CATEGORÍAS
# ════════════════════════════════════════════════════════════

@app.get("/categorias", response_model=List[CategoriaResponse], tags=["Categorías"])
def list_categorias(current_user: dict = Depends(get_current_user)):
    user_id = int(current_user["sub"])
    with DBConn() as (cur, _):
        cur.execute(
            "SELECT id, nombre, color, icono, orden "
            "FROM categorias WHERE user_id = %s ORDER BY orden ASC",
            (user_id,)
        )
        return cur.fetchall()


@app.post("/categorias", response_model=CategoriaResponse, status_code=201, tags=["Categorías"])
def create_categoria(body: CategoriaCreate, current_user: dict = Depends(get_current_user)):
    user_id = int(current_user["sub"])
    with DBConn() as (cur, conn):
        # Calcular orden
        cur.execute(
            "SELECT COALESCE(MAX(orden), 0) + 1 as next_orden "
            "FROM categorias WHERE user_id = %s",
            (user_id,)
        )
        orden = body.orden if body.orden is not None else cur.fetchone()["next_orden"]

        cur.execute(
            "INSERT INTO categorias (user_id, nombre, color, icono, orden) "
            "VALUES (%s, %s, %s, %s, %s)",
            (user_id, body.nombre, body.color, body.icono, orden)
        )
        conn.commit()
        new_id = cur.lastrowid

    return {"id": new_id, "nombre": body.nombre, "color": body.color,
            "icono": body.icono, "orden": orden}


@app.put("/categorias/{cat_id}", response_model=CategoriaResponse, tags=["Categorías"])
def update_categoria(
    cat_id: int,
    body: CategoriaUpdate,
    current_user: dict = Depends(get_current_user)
):
    user_id = int(current_user["sub"])
    with DBConn() as (cur, conn):
        cur.execute(
            "SELECT * FROM categorias WHERE id = %s AND user_id = %s",
            (cat_id, user_id)
        )
        cat = cur.fetchone()
        if not cat:
            raise HTTPException(status_code=404, detail="Categoría no encontrada")

        updates = {k: v for k, v in body.model_dump().items() if v is not None}
        if updates:
            cols = ", ".join(f"{k} = %s" for k in updates)
            cur.execute(
                f"UPDATE categorias SET {cols} WHERE id = %s AND user_id = %s",
                (*updates.values(), cat_id, user_id)
            )
            conn.commit()

        cur.execute("SELECT id, nombre, color, icono, orden FROM categorias WHERE id = %s", (cat_id,))
        return cur.fetchone()


@app.delete("/categorias/{cat_id}", status_code=204, tags=["Categorías"])
def delete_categoria(cat_id: int, current_user: dict = Depends(get_current_user)):
    user_id = int(current_user["sub"])
    with DBConn() as (cur, conn):
        cur.execute(
            "SELECT id FROM categorias WHERE id = %s AND user_id = %s AND nombre != 'General'",
            (cat_id, user_id)
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="Categoría no encontrada o es General")

        # Mover passwords a General
        cur.execute(
            "SELECT id FROM categorias WHERE user_id = %s AND nombre = 'General'", (user_id,)
        )
        general = cur.fetchone()
        if general:
            cur.execute(
                "UPDATE passwords SET categoria_id = %s WHERE categoria_id = %s",
                (general["id"], cat_id)
            )
        cur.execute("DELETE FROM categorias WHERE id = %s", (cat_id,))
        conn.commit()


# ════════════════════════════════════════════════════════════
#  CONTRASEÑAS
# ════════════════════════════════════════════════════════════

@app.get("/passwords", response_model=List[PasswordListItem], tags=["Contraseñas"])
def list_passwords(
    categoria_id: Optional[int] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Lista contraseñas — sin desencriptar (usar GET /passwords/{id} para ver)."""
    user_id = int(current_user["sub"])
    with DBConn() as (cur, _):
        query  = ("SELECT id, title as titulo, user as usuario, url, notes as notas, "
                  "categoria_id, has_expiration as tiene_vencimiento, "
                  "days_to_expiration as dias_vencimiento, "
                  "inicio_vencimiento FROM passwords WHERE user_id = %s")
        params = [user_id]

        if categoria_id:
            query += " AND categoria_id = %s"
            params.append(categoria_id)
        if search:
            query += " AND (title LIKE %s OR user LIKE %s OR url LIKE %s)"
            params += [f"%{search}%", f"%{search}%", f"%{search}%"]

        query += " ORDER BY title ASC"
        cur.execute(query, params)
        return cur.fetchall()


@app.get("/passwords/{pwd_id}", response_model=PasswordResponse, tags=["Contraseñas"])
def get_password(pwd_id: int, current_user: dict = Depends(get_current_user)):
    """Obtiene una contraseña desencriptada."""
    user_id = int(current_user["sub"])
    with DBConn() as (cur, _):
        # Necesitamos el salt del usuario para desencriptar
        cur.execute("SELECT salt FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        cur.execute(
            "SELECT id, title as titulo, user as usuario, encrypted_password, "
            "url, notes as notas, categoria_id, has_expiration as tiene_vencimiento, "
            "days_to_expiration as dias_vencimiento, inicio_vencimiento "
            "FROM passwords WHERE id = %s AND user_id = %s",
            (pwd_id, user_id)
        )
        pwd = cur.fetchone()
        if not pwd:
            raise HTTPException(status_code=404, detail="Contraseña no encontrada")

    # Desencriptar — la master password del usuario ES su contraseña de login
    # Nota: en la app desktop la master password = contraseña de login
    # La API necesita el token para obtener la master password
    # Por seguridad, el cliente debe enviar la master password en el header
    # Por ahora retornamos encriptada — el cliente desencripta localmente
    # TODO: implementar desencriptado con master password del token
    try:
        # Intentar desencriptar (requiere que el cliente envíe master_password)
        pwd["password"] = "[encriptado - usar /passwords/{id}/decrypt]"
    except Exception:
        pwd["password"] = "[error al desencriptar]"

    return pwd


@app.post("/passwords/{pwd_id}/decrypt", response_model=PasswordResponse, tags=["Contraseñas"])
def decrypt_password_endpoint(
    pwd_id: int,
    master_password: str,
    current_user: dict = Depends(get_current_user)
):
    """Desencripta y retorna una contraseña específica."""
    user_id = int(current_user["sub"])
    with DBConn() as (cur, _):
        cur.execute("SELECT salt FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()

        cur.execute(
            "SELECT id, title as titulo, user as usuario, encrypted_password, "
            "url, notes as notas, categoria_id, has_expiration as tiene_vencimiento, "
            "days_to_expiration as dias_vencimiento, inicio_vencimiento "
            "FROM passwords WHERE id = %s AND user_id = %s",
            (pwd_id, user_id)
        )
        pwd = cur.fetchone()
        if not pwd:
            raise HTTPException(status_code=404, detail="Contraseña no encontrada")

    try:
        plain = decrypt_password(pwd["encrypted_password"], master_password, user["salt"])
        pwd["password"] = plain
    except Exception:
        raise HTTPException(status_code=400, detail="Master password incorrecta")

    return pwd


@app.post("/passwords", response_model=PasswordListItem, status_code=201, tags=["Contraseñas"])
def create_password(
    body: PasswordCreate,
    master_password: str,
    current_user: dict = Depends(get_current_user)
):
    user_id = int(current_user["sub"])
    with DBConn() as (cur, conn):
        cur.execute("SELECT salt FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        encrypted = encrypt_password(body.password, master_password, user["salt"])

        cur.execute(
            "INSERT INTO passwords (user_id, categoria_id, title, user, "
            "encrypted_password, has_expiration, days_to_expiration, "
            "inicio_vencimiento, notes, url) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (user_id, body.categoria_id, body.titulo, body.usuario,
             encrypted, body.tiene_vencimiento, body.dias_vencimiento,
             body.inicio_vencimiento, body.notas, body.url)
        )
        conn.commit()
        new_id = cur.lastrowid

    return {
        "id": new_id, "titulo": body.titulo, "usuario": body.usuario,
        "url": body.url, "notas": body.notas, "categoria_id": body.categoria_id,
        "tiene_vencimiento": body.tiene_vencimiento,
        "dias_vencimiento": body.dias_vencimiento,
        "inicio_vencimiento": body.inicio_vencimiento,
    }


@app.put("/passwords/{pwd_id}", response_model=PasswordListItem, tags=["Contraseñas"])
def update_password(
    pwd_id: int,
    body: PasswordUpdate,
    current_user: dict = Depends(get_current_user),
    master_password: Optional[str] = None,
):
    user_id = int(current_user["sub"])
    with DBConn() as (cur, conn):
        cur.execute(
            "SELECT * FROM passwords WHERE id = %s AND user_id = %s",
            (pwd_id, user_id)
        )
        pwd = cur.fetchone()
        if not pwd:
            raise HTTPException(status_code=404, detail="Contraseña no encontrada")

        updates = {}
        data = body.model_dump(exclude_none=True)

        if "titulo"   in data: updates["title"]              = data["titulo"]
        if "usuario"  in data: updates["user"]               = data["usuario"]
        if "url"      in data: updates["url"]                = data["url"]
        if "notas"    in data: updates["notes"]              = data["notas"]
        if "categoria_id"      in data: updates["categoria_id"]      = data["categoria_id"]
        if "tiene_vencimiento" in data: updates["has_expiration"]     = data["tiene_vencimiento"]
        if "dias_vencimiento"  in data: updates["days_to_expiration"] = data["dias_vencimiento"]
        if "inicio_vencimiento" in data: updates["inicio_vencimiento"]= data["inicio_vencimiento"]

        if "password" in data and master_password:
            cur.execute("SELECT salt FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            updates["encrypted_password"] = encrypt_password(
                data["password"], master_password, user["salt"]
            )

        if updates:
            cols = ", ".join(f"{k} = %s" for k in updates)
            cur.execute(
                f"UPDATE passwords SET {cols} WHERE id = %s AND user_id = %s",
                (*updates.values(), pwd_id, user_id)
            )
            conn.commit()

        cur.execute(
            "SELECT id, title as titulo, user as usuario, url, notes as notas, "
            "categoria_id, has_expiration as tiene_vencimiento, "
            "days_to_expiration as dias_vencimiento, inicio_vencimiento "
            "FROM passwords WHERE id = %s",
            (pwd_id,)
        )
        return cur.fetchone()


@app.delete("/passwords/{pwd_id}", status_code=204, tags=["Contraseñas"])
def delete_password(pwd_id: int, current_user: dict = Depends(get_current_user)):
    user_id = int(current_user["sub"])
    with DBConn() as (cur, conn):
        cur.execute(
            "DELETE FROM passwords WHERE id = %s AND user_id = %s",
            (pwd_id, user_id)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Contraseña no encontrada")


# ════════════════════════════════════════════════════════════
#  GENERADOR DE CONTRASEÑAS
# ════════════════════════════════════════════════════════════

@app.post("/generate-password", tags=["Utilidades"])
def generate_password(body: GeneratePasswordRequest):
    chars = ""
    if body.uppercase:  chars += string.ascii_uppercase
    if body.lowercase:  chars += string.ascii_lowercase
    if body.numbers:    chars += string.digits
    if body.symbols:    chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if body.exclude_ambiguous:
        for c in "0O1lI":
            chars = chars.replace(c, "")

    if not chars:
        raise HTTPException(status_code=400, detail="Seleccioná al menos un tipo de caracter")

    password = "".join(random.SystemRandom().choices(chars, k=body.length))
    return {"password": password}


# ════════════════════════════════════════════════════════════
#  ADMIN
# ════════════════════════════════════════════════════════════

@app.get("/admin/users", response_model=List[UserResponse], tags=["Admin"])
def list_users(admin: dict = Depends(require_admin)):
    with DBConn() as (cur, _):
        cur.execute("SELECT id, username, role, status FROM users ORDER BY id")
        return cur.fetchall()


@app.get("/admin/users/pending", response_model=List[UserResponse], tags=["Admin"])
def list_pending(admin: dict = Depends(require_admin)):
    with DBConn() as (cur, _):
        cur.execute(
            "SELECT id, username, role, status FROM users WHERE status = 'pending'"
        )
        return cur.fetchall()


@app.put("/admin/users/{user_id}/status", tags=["Admin"])
def update_user_status(
    user_id: int,
    body: UpdateUserStatus,
    admin: dict = Depends(require_admin)
):
    if body.status not in ("active", "pending", "rejected"):
        raise HTTPException(status_code=400, detail="Status inválido")

    with DBConn() as (cur, conn):
        cur.execute(
            "UPDATE users SET status = %s WHERE id = %s",
            (body.status, user_id)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        # Log auditoría
        cur.execute(
            "INSERT INTO user_audit_log "
            "(admin_id, admin_username, target_user_id, target_username, action, new_value) "
            "VALUES (%s, %s, %s, (SELECT username FROM users WHERE id=%s), %s, %s)",
            (int(admin["sub"]), admin["username"], user_id, user_id, "change_status", body.status)
        )
        conn.commit()

    return {"message": f"Status actualizado a {body.status}"}


@app.put("/admin/users/{user_id}/role", tags=["Admin"])
def update_user_role(
    user_id: int,
    body: UpdateUserRole,
    admin: dict = Depends(require_admin)
):
    if body.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Rol inválido")

    with DBConn() as (cur, conn):
        cur.execute(
            "UPDATE users SET role = %s WHERE id = %s", (body.role, user_id)
        )
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return {"message": f"Rol actualizado a {body.role}"}


@app.delete("/admin/users/{user_id}", status_code=204, tags=["Admin"])
def delete_user(user_id: int, admin: dict = Depends(require_admin)):
    admin_id = int(admin["sub"])
    if user_id == admin_id:
        raise HTTPException(status_code=400, detail="No podés eliminar tu propia cuenta")

    with DBConn() as (cur, conn):
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")


@app.get("/admin/audit-log", response_model=List[AuditLogResponse], tags=["Admin"])
def get_audit_log(limit: int = 100, admin: dict = Depends(require_admin)):
    with DBConn() as (cur, _):
        cur.execute(
            "SELECT id, admin_username, target_username, action, "
            "old_value, new_value, "
            "DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at "
            "FROM user_audit_log ORDER BY created_at DESC LIMIT %s",
            (limit,)
        )
        return cur.fetchall()


# ════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ════════════════════════════════════════════════════════════

@app.get("/health", tags=["Utilidades"])
def health():
    try:
        with DBConn() as (cur, _):
            cur.execute("SELECT 1")
        return {"status": "ok", "db": "connected"}
    except Exception as e:
        return {"status": "error", "db": str(e)}
