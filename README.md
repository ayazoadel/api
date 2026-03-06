# API — Gestor de Contraseñas

## Archivos
```
api/
├── main.py          ← App FastAPI con todos los endpoints
├── auth.py          ← JWT tokens
├── crypto.py        ← Encriptación (igual que la app de escritorio)
├── db.py            ← Pool de conexiones MySQL
├── config.py        ← Variables de entorno
├── schemas.py       ← Modelos Pydantic
├── requirements.txt
├── Procfile         ← Para Railway
├── railway.json     ← Config de Railway
└── .env.example     ← Variables a configurar
```

## Deploy en Railway

### 1. Crear nuevo servicio
- En tu proyecto Railway → "New Service" → "GitHub Repo"
- O usar Railway CLI: `railway up`

### 2. Variables de entorno en Railway
En el servicio de la API → Variables, agregar:
```
DB_HOST=hopper.proxy.rlwy.net
DB_PORT=37535
DB_NAME=railway
DB_USER=root
DB_PASSWORD=tu_password
JWT_SECRET=genera_una_clave_con: python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Verificar que funciona
```
GET https://tu-api.railway.app/health
```

## Probar localmente
```bash
pip install -r requirements.txt
cp .env.example .env   # editar con tus datos
uvicorn main:app --reload
```
Documentación interactiva en: http://localhost:8000/docs

## Endpoints principales

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | /auth/login | Login → JWT token |
| POST | /auth/register | Solicitar cuenta |
| GET  | /categorias | Listar categorías |
| GET  | /passwords | Listar contraseñas |
| POST | /passwords/{id}/decrypt | Ver contraseña desencriptada |
| POST | /generate-password | Generar contraseña aleatoria |
| GET  | /admin/users/pending | Usuarios pendientes (admin) |
| PUT  | /admin/users/{id}/status | Aprobar/rechazar usuario (admin) |

Documentación completa: `https://tu-api.railway.app/docs`
