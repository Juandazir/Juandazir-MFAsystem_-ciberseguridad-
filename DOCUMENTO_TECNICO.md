# Sistema MFA — Documento Técnico de Seguridad

## 1. Resumen Ejecutivo

Sistema de autenticación multifactor (MFA) con soporte para TOTP, SMS, WhatsApp y email. Implementa registro, inicio de sesión, verificación de contacto, recuperación de contraseña, panel de administración y perfiles de usuario. Construido en Node.js puro (sin frameworks web) con SQLite como base de datos.

---

## 2. Arquitectura del Sistema

### 2.1 Stack Tecnológico

| Componente       | Tecnología                                 |
|------------------|--------------------------------------------|
| Servidor HTTP    | `http` module (Node.js nativo, sin Express)|
| Base de datos    | SQLite vía `better-sqlite3` (WAL mode)     |
| JWT              | HMAC-SHA256, implementación manual          |
| Hash contraseñas | scrypt (Node.js `crypto`)                  |
| TOTP             | RFC 6238, HMAC-SHA1, 6 dígitos, ±2 ventanas|
| Email            | Nodemailer (SMTP)                          |
| SMS/WhatsApp     | Twilio SDK + CallMeBot API + email-to-SMS  |
| QR               | `qrcode` npm package                       |
| Frontend         | HTML+CSS+JS vanilla (SPA, ~1400 líneas)    |

### 2.2 Estructura de Archivos

```
mfa-ciberseguridad/
├── server.js                    # Servidor principal (~1327 líneas)
├── package.json
├── database/
│   ├── data.sqlite              # Base de datos SQLite
│   ├── data.json.backup         # Backup migración JSON→SQLite
│   ├── email-config.json        # Configuración SMTP
│   ├── twilio-config.json       # Configuración Twilio (eliminado)
│   ├── callmebot-config.json    # Configuración CallMeBot API
│   └── sms-carriers.json        # Operadores Colombia (email-to-SMS)
└── frontend/public/
    └── index.html               # SPA frontend
```

### 2.3 Diagrama de Flujo de Autenticación

```
[Usuario] → Login (email+password)
    ├─ ¿Credenciales válidas?
    │   ├─ No  → 401 + incrementa failed_attempts
    │   │        └─ ¿failed_attempts ≥ 3? → Lockout 15 min
    │   └─ Sí  → ¿MFA habilitado?
    │       ├─ No  → JWT access token (1 hora)
    │       └─ Sí  → temp_token (5 min) + lista métodos
    │               └─ [Usuario] selecciona método
    │                   ├─ TOTP  → verifica HMAC-SHA1
    │                   ├─ SMS   → send-otp → verify-otp
    │                   ├─ WhatsApp → send-otp → verify-otp
    │                   └─ Email → send-otp → verify-otp
    │                   └─ ¿OTP válido?
    │                       ├─ No  → 401 + max 5 intentos/OTP
    │                       └─ Sí  → JWT access token (1 hora)
    └─ [Dashboard] ← acceso protegido
```

---

## 3. Implementación de Seguridad

### 3.1 Hash de Contraseñas (scrypt)

```javascript
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');  // 128 bits aleatorios
  return `${salt}:${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}
```

- **scrypt**: algoritmo de derivación de clave con uso intensivo de memoria y CPU.
- **Salt**: 16 bytes aleatorios por usuario, único.
- **Output**: 64 bytes (512 bits) de hash.
- **Formato almacenado**: `salt:hash` — permite verificación independiente.

Resistencia contra:
- **Rainbow tables**: neutralizadas por salt único por usuario.
- **Ataques de fuerza bruta**: scrypt es intencionalmente lento y costoso en memoria.
- **Ataques de diccionario**: misma protección.

### 3.2 JSON Web Tokens (JWT)

#### 3.2.1 Creación

```javascript
function createJWT(payload, expiresIn = JWT_EXPIRY) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now(), exp: Date.now() + expiresIn })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}
```

#### 3.2.2 Verificación

```javascript
function verifyJWT(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[2]))) return null;
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  if (payload.exp < Date.now()) return null;
  return payload;
}
```

| Propiedad        | Valor                           |
|------------------|---------------------------------|
| Algoritmo        | HS256 (HMAC-SHA256)             |
| Secreto          | 32 bytes (256 bits) aleatorios  |
| Expiración       | Access: 3600s (1h), Temp: 300s (5min) |
| Protección timing| `crypto.timingSafeEqual`        |
| Payload access   | `{ userId, email, mfa_methods }`|
| Payload temp     | `{ userId, purpose: 'mfa_verify' }`|

#### 3.2.3 Tipos de Token

| Token        | Lifetime | Propósito                                    |
|-------------|----------|----------------------------------------------|
| `access`    | 1 hora   | Acceso completo a API autenticada            |
| `temp_token`| 5 minutos| Flujo MFA: enviar/verificar OTP antes del acceso completo |

**Análisis de seguridad**: El `temp_token` permite acceso a endpoints autenticados durante 5 minutos incluso sin completar MFA. Esto es necesario para que el usuario pueda solicitar el envío del OTP. Sin embargo, un atacante que intercepte este token temporal tendría una ventana de 5 minutos para usar las siguientes APIs:
- `GET /api/accounts/profile/` — leer datos del perfil
- `PUT /api/accounts/profile/` — actualizar perfil (si conoce la estructura)
- `POST /api/accounts/send-otp/` — solicitar envío de OTP

### 3.3 TOTP (Time-based One-Time Password)

Implementación según **RFC 6238**:

- **Algoritmo**: HMAC-SHA1
- **Dígitos**: 6
- **Período**: 30 segundos
- **Ventana de verificación**: ±2 intervalos (±60 segundos de tolerancia de reloj)
- **Secreto**: 20 bytes aleatorios, codificado en base32 para el QR

El TOTP se verifica contra 5 ventanas de tiempo (actual ±2) para tolerar desincronización de reloj.

### 3.4 OTP (One-Time Password para SMS/WhatsApp/Email)

- **Longitud**: 6 dígitos numéricos
- **Expiración**: 5 minutos
- **Límite de intentos**: 5 por código OTP (se invalida al exceder)
- **Rate limiting global**: 5 solicitudes de envío por minuto por IP
- **Rate limiting verificación**: 10 intentos por minuto por IP
- **Almacenamiento**: En memoria (Map), no persistente

### 3.5 Rate Limiting

| Endpoint               | Límite     | Ventana | Clave                  |
|------------------------|-----------|---------|------------------------|
| `POST /login/`         | 10        | 1 min   | `login:{IP}`           |
| `POST /send-otp/`      | 5         | 1 min   | `sendotp:{IP}`         |
| `POST /verify-mfa/`    | 10        | 1 min   | `verifymfa:{IP}`       |
| `POST /forgot-password/`| 3        | 1 min   | `forgot:{IP}`          |
| `POST /reset-password/`| 5         | 1 min   | `reset:{IP}`           |

Implementación manual con `Map` y limpieza periódica cada 5 minutos.

### 3.6 Bloqueo de Cuenta (Account Lockout)

- **Umbral**: 3 intentos fallidos de inicio de sesión consecutivos
- **Duración**: 15 minutos desde el último intento fallido
- **Desbloqueo automático**: tras la ventana de 15 minutos, el siguiente inicio de sesión exitoso desbloquea

### 3.7 Headers de Seguridad HTTP

```javascript
'X-Content-Type-Options': 'nosniff'
'X-Frame-Options': 'DENY'
'X-XSS-Protection': '1; mode=block'
'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
'Referrer-Policy': 'strict-origin-when-cross-origin'
'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'"
'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
'Pragma': 'no-cache'
```

### 3.8 Validación de Entrada

| Campo       | Validación                                         |
|-------------|---------------------------------------------------|
| Email       | `^[^\s@]+@[^\s@]+\.[^\s@]+$` (formato básico)    |
| Teléfono    | `^\+?[\d\s\-()]{7,20}$`                          |
| Contraseña  | Mínimo 6 caracteres, máximo 128                   |
| OTP/TOTP    | String, trim, comparado como string               |

### 3.9 Entrega de Códigos (SMS/WhatsApp)

Cadena de entrega para SMS:

```
Twilio SMS → Twilio WhatsApp → CallMeBot (free) → email-to-SMS gateway → consola (fallback)
```

Cadena de entrega para WhatsApp:

```
Twilio WhatsApp → CallMeBot (free) → consola (fallback)
```

Cada eslabón registra éxito/fallo en logs. El código siempre se muestra en consola y en el frontend (modo desarrollo).

---

## 4. Análisis de Vulnerabilidades y Mitigaciones

### 4.1 Vulnerabilidades Identificadas

| # | Vulnerabilidad                        | Severidad | Estado     |
|---|---------------------------------------|-----------|------------|
| 1 | **HTTP plano** — sin TLS/HTTPS        | CRÍTICA   | ⚠ No mitigado |
| 2 | **OTP en respuesta JSON** — el código se devuelve en el body | MEDIA | Por diseño (dev) |
| 3 | **Sin JWT ID (jti)** — no se pueden revocar tokens individualmente | MEDIA | ⚠ No mitigado |
| 4 | **temp_token con acceso a API** — token MFA permite acceder a endpoints autenticados | BAJA | Por diseño |
| 5 | **CORS permisivo** — `Access-Control-Allow-Origin: *` | BAJA | Aceptable para MVP |
| 6 | **Sin refresh tokens** — el token de acceso expira y requiere relogin | BAJA | Por diseño |
| 7 | **Contraseña mínima 6 caracteres** — no se exige complejidad | BAJA | Mejorable |
| 8 | **No hay bloqueo por IP** — el rate limiting es por IP pero no hay bloqueo permanente | BAJA | ⚠ No mitigado |

### 4.2 Mitigaciones Implementadas

| Amenaza                                   | Mitigación                                         |
|-------------------------------------------|----------------------------------------------------|
| Intercepción de tráfico (sniffing)        | ⚠ Pendiente: implementar HTTPS                    |
| Fuerza bruta a contraseñas                | Rate limiting + account lockout + scrypt          |
| Fuerza bruta a OTP                        | 5 intentos máx por OTP + rate limiting por IP     |
| Replay attack (OTP)                       | OTP de un solo uso, expira en 5 min               |
| Manipulación de JWT                       | Firma HMAC-SHA256 + timingSafeEqual               |
| Timing attack en JWT                      | `crypto.timingSafeEqual`                          |
| Cross-Site Scripting (XSS)                | CSP headers                                       |
| Clickjacking                              | `X-Frame-Options: DENY`                           |
| MIME sniffing                             | `X-Content-Type-Options: nosniff`                 |
| Reuse de contraseñas                      | (No implementado: recomendado verificar HaveIBeenPwned) |
| Ataques de diccionario a hashes           | scrypt + salt único por usuario                   |
| Ataques de canal lateral (timing)         | timingSafeEqual en JWT y verificación de hash     |

---

## 5. Flujo de Tokens (Seguridad)

### 5.1 Ciclo de Vida del Token

```
REGISTRO
  └→ No genera token (solo crea usuario)

LOGIN (sin MFA)
  └→ createJWT({ userId, email, mfa_methods: [] }, 3600000)
  └→ Almacenado en memoria (variable JS)
  └→ Enviado en Header: Authorization: Bearer <token>
  └→ Verificado en cada request con verifyJWT()
  └→ Expira en 1 hora → usuario debe reloguearse

LOGIN (con MFA)
  └→ createJWT({ userId, purpose: 'mfa_verify' }, 300000)  ← temp_token
  └→ Frontend envía temp_token al solicitar send-otp
  └→ verify-mfa exitoso → createJWT({ userId, email, mfa_methods }, 3600000)
  └→ temp_token expira en 5 min
```

### 5.2 Recomendaciones de Seguridad para Producción

1. **Implementar HTTPS** con certificados Let's Encrypt (gratis)
2. **Agregar JWT ID (`jti`)** con blacklist en Redis o SQLite para revocación
3. **No devolver el OTP en la respuesta JSON** en producción (flag `NODE_ENV=production`)
4. **Exigir complejidad de contraseña**: mayúsculas, números, símbolos, mínimo 8 caracteres
5. **Agregar refresh tokens** con rotación para evitar relogin frecuente
6. **Implementar bloqueo permanente por IP** después de N rate-limit violations
7. **Restringir CORS** a dominios específicos en producción
8. **Validar `purpose` del temp_token** — verificar que dice `'mfa_verify'` en `getAuthUser`

---

## 6. API Reference

| Método | Ruta                             | Auth       | Descripción                          |
|--------|----------------------------------|------------|--------------------------------------|
| POST   | `/api/accounts/register/`        | No         | Registrar nuevo usuario              |
| POST   | `/api/accounts/login/`           | No         | Iniciar sesión                       |
| POST   | `/api/accounts/verify-mfa/`      | No         | Verificar código MFA                 |
| GET    | `/api/accounts/profile/`         | Bearer     | Obtener perfil                       |
| PUT    | `/api/accounts/profile/`         | Bearer     | Actualizar perfil                    |
| POST   | `/api/accounts/send-otp/`        | Bearer     | Enviar OTP (email/sms/whatsapp)      |
| POST   | `/api/accounts/verify-otp/`      | Bearer     | Verificar OTP de contacto            |
| POST   | `/api/accounts/mfa/toggle/`      | Bearer     | Activar/desactivar método MFA        |
| POST   | `/api/accounts/mfa/setup-totp/`  | Bearer     | Configurar TOTP (genera secreto+QR)  |
| POST   | `/api/accounts/forgot-password/` | No         | Solicitar reset de contraseña        |
| POST   | `/api/accounts/reset-password/`  | No         | Resetear contraseña con token        |
| GET    | `/api/admin/users/`              | Admin      | Listar usuarios                      |
| GET    | `/api/admin/users/:id/`          | Admin      | Obtener usuario                      |
| PUT    | `/api/admin/users/:id/`          | Admin      | Actualizar usuario                   |
| DELETE | `/api/admin/users/:id/`          | Admin      | Eliminar usuario                     |
| POST   | `/api/admin/users/:id/toggle-lock/` | Admin   | Bloquear/desbloquear                 |
| POST   | `/api/admin/users/:id/reset-mfa/` | Admin     | Resetear MFA                         |
| GET    | `/api/admin/email-config/`       | Admin      | Obtener config SMTP                  |
| PUT    | `/api/admin/email-config/`       | Admin      | Guardar config SMTP                  |
| GET    | `/api/admin/twilio-config/`      | Admin      | Obtener config Twilio                |
| PUT    | `/api/admin/twilio-config/`      | Admin      | Guardar config Twilio                |
| GET    | `/api/admin/callmebot-config/`   | Admin      | Obtener config CallMeBot             |
| PUT    | `/api/admin/callmebot-config/`   | Admin      | Guardar config CallMeBot             |

---

## 7. Dependencias y Licencias

| Paquete           | Versión | Propósito                        |
|-------------------|---------|----------------------------------|
| `better-sqlite3`  | ^11     | Base de datos SQLite síncrona    |
| `qrcode`          | ^1      | Generación de códigos QR (TOTP)  |
| `sql.js`          | ^1      | (Legado, para migración JSON)    |
| `nodemailer`      | ^6      | Envío de emails SMTP             |
| `twilio`          | ^5      | SDK de Twilio (SMS/WhatsApp)     |

---

## 8. Glosario

| Término         | Definición                                                   |
|-----------------|--------------------------------------------------------------|
| TOTP            | Time-based One-Time Password — código efímero que cambia cada 30s |
| OTP             | One-Time Password — código de un solo uso, típicamente 6 dígitos |
| JWT             | JSON Web Token — token autocontenido con firma criptográfica |
| HMAC-SHA256     | Algoritmo de firma usando clave secreta y SHA-256            |
| scrypt          | Función de derivación de clave con uso intensivo de memoria  |
| MFA             | Multi-Factor Authentication — autenticación de múltiples factores |
| WAL mode        | Write-Ahead Logging — modo de SQLite para mejor concurrencia |
| timingSafeEqual | Comparación de buffers en tiempo constante (previene timing attacks) |

---

## 9. Conclusión

El sistema implementa prácticas de seguridad sólidas en varios frentes (hashing con scrypt, JWT con HMAC-SHA256 y `timingSafeEqual`, rate limiting, account lockout, OTP con expiración y límite de intentos, headers HTTP de seguridad). Las principales debilidades son la ausencia de HTTPS (crítica para producción) y la falta de revocación de tokens. Para un despliegue en producción se recomienda priorizar la implementación de TLS/SSL.
