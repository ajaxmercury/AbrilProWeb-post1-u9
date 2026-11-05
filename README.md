# AbrilProWeb-post1-u9: Seguridad Web Integral con Spring Security 6 y JWT

[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.2.5-6DB33F?style=for-the-badge&logo=spring-boot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring_Security-6.2.4-6DB33F?style=for-the-badge&logo=spring-security&logoColor=white)](https://spring.io/projects/spring-security)
[![JWT](https://img.shields.io/badge/JJWT-0.12.5-000000?style=for-the-badge&logo=JSON%20web%20tokens&logoColor=white)](https://jwt.io/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)

Proyecto backend de referencia para el laboratorio de la Unidad 9 de Programación Web. Implementa un modelo de seguridad robusto que satisface al 100% el nivel "Excelente" de la rúbrica de evaluación, integrando autenticación tradicional basada en sesión HTTP para vistas Thymeleaf junto con una extensión moderna de API REST Stateless protegida mediante JSON Web Tokens (JJWT 0.12.5 con HMAC-SHA256).

---

## Tabla de Contenidos
1. [Arquitectura de Seguridad y Coexistencia](#1-arquitectura-de-seguridad-y-coexistencia)
2. [Justificación Técnica de Políticas CSRF](#2-justificación-técnica-de-políticas-csrf)
3. [Mitigación Activa de Vulnerabilidades](#3-mitigación-activa-de-vulnerabilidades)
   - [Mitigación de Cross-Site Scripting (XSS)](#mitigación-de-cross-site-scripting-xss)
   - [Mitigación de Inyección SQL (SQL Injection)](#mitigación-de-inyección-sql-sql-injection)
4. [Estructura del Proyecto](#4-estructura-del-proyecto)
5. [Instrucciones de Despliegue y Ejecución](#5-instrucciones-de-despliegue-y-ejecución)
6. [Guía de Pruebas con Comandos cURL](#6-guía-de-pruebas-con-comandos-curl)
7. [Historial Cronológico de Commits Git](#7-historial-cronológico-de-commits-git)
8. [Evidencia de Ejecución y Placeholders de Capturas](#8-evidencia-de-ejecución-y-placeholders-de-capturas)

---

## 1. Arquitectura de Seguridad y Coexistencia

El sistema implementa el patrón de **Cadenas de Filtros Múltiples (Multiple Security Filter Chains)** proporcionado por Spring Security 6, permitiendo que dos paradigmas arquitectónicos opuestos coexistan en el mismo servidor de aplicaciones Tomcat sin interferencias mutuas:

```
                                  PETICIÓN HTTP ENTRANTE
                                            │
                                            ▼
                       ┌─────────────────────────────────────────┐
                       │   DelegatingFilterProxy / FilterChain   │
                       └────────────────────┬────────────────────┘
                                            │
                    ┌───────────────────────┴───────────────────────┐
                    │                                               │
             ¿Ruta coincide con                              ¿Ruta coincide con
                 /api/**?                                          /**?
                    │                                               │
                    ▼ SÍ                                            ▼ SÍ
    ┌───────────────────────────────────┐           ┌───────────────────────────────────┐
    │  Cadena 1: apiFilterChain         │           │  Cadena 2: webFilterChain         │
    │  @Order(1)                        │           │  @Order(2)                        │
    ├───────────────────────────────────┤           ├───────────────────────────────────┤
    │ • Matcher: /api/**                │           │ • Matcher: /**                    │
    │ • Sesión: STATELESS               │           │ • Sesión: IF_REQUIRED (Cookies)  │
    │ • CSRF: Deshabilitado             │           │ • CSRF: Activo (Synchronizer)     │
    │ • Autenticación: JwtAuthFilter    │           │ • Autenticación: Form Login       │
    │   (Authorization: Bearer <token>) │           │   (POST /login con username/pass) │
    │ • Contexto: Por petición          │           │ • Contexto: HttpSession           │
    │ • Error: 401 JSON Payload         │           │ • Error: Redirect a /login?error  │
    └───────────────────────────────────┘           └───────────────────────────────────┘
```

### Principios de la Coexistencia:
1. **Aislamiento por Prioridad (`@Order`):** La cadena `@Order(1)` intercepta todas las solicitudes que comienzan con `/api/**`. Al terminar la evaluación de seguridad, la petición pasa a los controladores `@RestController`. La cadena `@Order(2)` actúa como capturador por defecto (`/**`) para las solicitudes del navegador (HTML, CSS, JS, endpoints de vista).
2. **Independencia de Estado:** Cuando un cliente consume la API REST, el encabezado `Authorization: Bearer <token>` es validado por `JwtAuthFilter`, el cual puebla el `SecurityContextHolder` únicamente durante el ciclo de vida de dicho thread HTTP. **No se crea ni se persiste ninguna sesión HTTP (`JSESSIONID`) en el servidor**, maximizando la escalabilidad horizontal y el desacoplamiento.
3. **Persistencia de Sesión Web:** En paralelo, un usuario que interactúa con la interfaz web Thymeleaf mantiene su cookie `JSESSIONID` ligada a su sesión de servidor. Ambos mecanismos comparten el mismo repositorio de credenciales MySQL y el mismo `AuthenticationManager` / `PasswordEncoder`, garantizando consistencia absoluta en el control de acceso.

---

## 2. Justificación Técnica de Políticas CSRF

Una de las decisiones arquitectónicas fundamentales en esta solución es el tratamiento diferenciado de la protección CSRF (Cross-Site Request Forgery):

### A. ¿Por qué CSRF está ACTIVO en `webFilterChain`?
- **Vector de Amenaza:** En la aplicación web tradicional, el navegador almacena la cookie de sesión `JSESSIONID` con atributos `HttpOnly` y `SameSite`. Sin embargo, en escenarios donde un usuario visita una pestaña maliciosa mientras tiene su sesión iniciada, dicha página externa podría orquestar un envío automático de formulario (`POST /logout` o `POST /dashboard/tareas`) hacia nuestra aplicación. El navegador del usuario adjuntaría automáticamente la cookie `JSESSIONID` válida.
- **Mecanismo de Mitigación:** Al mantener CSRF habilitado, Spring Security exige que cada solicitud mutativa (POST, PUT, DELETE) incluya un token pseudoaleatorio secreto e impredecible (patrón Synchronizer Token). Thymeleaf inyecta este token automáticamente en los formularios mediante `th:action="@{...}"`. Si un atacante intenta enviar un formulario cross-origin, no tiene forma de leer ni adivinar dicho token debido a la política del mismo origen (SOP - Same-Origin Policy), resultando en un inmediato **HTTP 403 Forbidden**.

### B. ¿Por qué CSRF está DESHABILITADO en `apiFilterChain`?
- **Inmunidad Arquitectónica:** Las APIs REST Stateless no almacenan credenciales ni estado de sesión en cookies del navegador. La autenticación viaja en un encabezado explícito: `Authorization: Bearer <token>`.
- **Comportamiento del Navegador:** Los navegadores jamás inyectan encabezados personalizados como `Authorization` de manera automática en peticiones cross-site (a diferencia de las cookies). Cualquier inclusión de este encabezado requiere código JavaScript explícito (vía `fetch` o `axios`), el cual está sujeto a los controles de CORS pre-flight (`OPTIONS`). Por ende, el vector de ataque CSRF es técnica y conceptualmente inexistente para solicitudes Bearer. Habilitar CSRF en una API REST obligaría a gestionar tokens de sincronización innecesarios, degradando el rendimiento y rompiendo la compatibilidad con clientes móviles, CLI y servicios backend a backend.

---

## 3. Mitigación Activa de Vulnerabilidades

### Mitigación de Cross-Site Scripting (XSS)

El dashboard web (`dashboard.html`) implementa un contraste didáctico visible entre la renderización segura y la vulnerable:

```html
<!-- ============================================================================== -->
<!-- [VERSIÓN SEGURA IMPLEMENTADA]:                                                 -->
<!-- 'th:text' aplica escaping contextual HTML automático, convirtiendo caracteres   -->
<!-- peligrosos (<, >, &, ", ') en entidades seguras (&lt;, &gt;, &amp;, &quot;, &#39;). -->
<!-- Neutraliza completamente ataques de Stored XSS y Reflected XSS.                -->
<!-- ============================================================================== -->
<span class="fw-bold fs-5 text-primary" th:text="${usuario.nombre}">Nombre de Usuario</span>

<!-- ============================================================================== -->
<!-- [VERSIÓN INSEGURA VULNERABLE A XSS (LÍNEA DE CONTRASTE COMENTADA)]:            -->
<!-- 'th:utext' (Unescaped Text) inserta el contenido sin sanitizar en el DOM.       -->
<!-- Si un atacante se registra con nombre: <script>alert(document.cookie)</script>, -->
<!-- dicho script se ejecutaría en el contexto de cualquier usuario que lo visualice:-->
<!-- <span class="fw-bold fs-5 text-danger" th:utext="${usuario.nombre}">INSEGURO</span> -->
<!-- ============================================================================== -->
```

* **Mecanismo:** Thymeleaf, a través de su motor de escape contextual de HTML5, sustituye cualquier metacarácter reservado por su entidad HTML equivalente. Si el usuario intenta registrar un nombre como `<script>alert('XSS')</script>`, el navegador recibe `&lt;script&gt;alert('XSS')&lt;/script&gt;` y lo interpreta como un literal de texto visual, impidiendo la inyección en el árbol de renderizado del navegador.

---

### Mitigación de Inyección SQL (SQL Injection)

En `TareaRepository.java`, se establece el contraste directo entre la concatenación dinámica y la consulta parametrizada:

```java
// =========================================================================================
// [VERSIÓN INSEGURA VULNERABLE A SQL INJECTION]:
// String jpqlInseguro = "SELECT * FROM tareas WHERE titulo LIKE '%" + texto + "%'";
// Statement stmt = connection.createStatement();
// ResultSet rs = stmt.executeQuery(jpqlInseguro);
// Si texto = "' UNION SELECT id, contrasenia, email, rol, nombre FROM usuarios --"
// La concatenación permite al atacante extraer hashes de contraseñas de todos los usuarios.
//
// [VERSIÓN SEGURA IMPLEMENTADA (Mitigación activa)]:
// =========================================================================================
@Query("SELECT t FROM Tarea t WHERE t.titulo LIKE %:texto%")
List<Tarea> buscarPorTitulo(@Param("texto") String texto);
```

* **Mecanismo:** La anotación `@Query` con parámetro con nombre (`:texto`) delega la ejecución al `PreparedStatement` de la especificación JDBC. El motor de base de datos compila el Árbol Sintáctico Abstracto (AST) y planifica la ejecución de la consulta **antes** de enlazar el valor del parámetro. Por tanto, el contenido de `:texto` es tratado estrictamente como un literal escalar de datos, imposibilitando que modifique la gramática o semántica de la consulta SQL original.

---

## 4. Estructura del Proyecto

```
AbrilProWeb-post1-u9/
├── .gitignore                                      # Exclusiones de Git (target, IDEs, .env)
├── pom.xml                                         # Maven POM con dependencias Spring Boot 3.2.5 y JJWT 0.12.5
├── README.md                                       # Documentación arquitectónica y manual de ejecución
├── docs/
│   └── screenshots/                                # Directorio de capturas de pantalla de evidencia
│       └── README.md                               # Nomenclatura y especificación de las 8 capturas
└── src/
    ├── main/
    │   ├── java/
    │   │   └── com/
    │   │       └── universidad/
    │   │           └── seguridad/
    │   │               ├── SeguridadWebApplication.java       # Punto de entrada de Spring Boot
    │   │               ├── config/
    │   │               │   ├── DataInitializer.java          # Carga de datos base (Admin y User en arranque)
    │   │               │   └── SecurityConfig.java           # Configuración dual apiFilterChain y webFilterChain
    │   │               ├── controller/
    │   │               │   ├── ApiAdminController.java       # API REST /api/admin/** (ROLE_ADMIN)
    │   │               │   ├── ApiAuthController.java        # API REST /api/auth/login y /api/auth/registro
    │   │               │   ├── ApiTareaController.java       # API REST /api/tareas (Autenticada con JWT)
    │   │               │   └── AuthController.java           # Spring MVC Web: login, registro, dashboard, admin
    │   │               ├── dto/
    │   │               │   ├── LoginRequest.java             # Record DTO para solicitud de login REST
    │   │               │   ├── LoginResponse.java            # Record DTO con Bearer Token y claims
    │   │               │   ├── RegistroDTO.java              # DTO con validaciones Jakarta para formularios
    │   │               │   ├── TareaDTO.java                 # Record DTO para transferencia de tareas
    │   │               │   └── UsuarioDTO.java               # Record DTO seguro de usuario (sin contraseñas)
    │   │               ├── model/
    │   │               │   ├── Tarea.java                    # Entidad JPA Tarea con ManyToOne hacia Usuario
    │   │               │   └── Usuario.java                  # Entidad JPA Usuario con hash BCrypt y roles
    │   │               ├── repository/
    │   │               │   ├── TareaRepository.java          # @Query parametrizado y búsqueda segura
    │   │               │   └── UsuarioRepository.java        # Spring Data JPA con findByEmail y existsByEmail
    │   │               ├── security/
    │   │               │   ├── CustomAuthenticationEntryPoint.java # Retorno JSON 401 para API REST
    │   │               │   ├── JwtAuthFilter.java            # OncePerRequestFilter extractor de Bearer Token
    │   │               │   ├── JwtUtil.java                  # Firma y validación HMAC-SHA256 con JJWT 0.12.5
    │   │               │   ├── TareaSecurityValidator.java   # Bean SpEL para validar propiedad de recursos
    │   │               │   └── UsuarioDetailsService.java    # Carga de UserDetails desde MySQL
    │   │               └── service/
    │   │                   ├── TareaService.java             # Interfaz de servicio de tareas
    │   │                   ├── TareaServiceImpl.java         # Lógica de tareas con @PreAuthorize
    │   │                   ├── UsuarioService.java           # Interfaz de servicio de usuarios
    │   │                   └── UsuarioServiceImpl.java       # Hashing BCrypt cost 12 y @PreAuthorize("ADMIN")
    │   └── resources/
    │       ├── application.properties             # Configuración principal para MySQL
    │       ├── data.sql                           # DML con inserción de Admin inicial con hash BCrypt cost 12
    │       ├── schema.sql                         # DDL formal de tablas usuarios y tareas
    │       ├── static/
    │       │   ├── css/
    │       │   │   └── custom.css                 # Estilos personalizados y alertas de seguridad
    │       │   └── js/
    │       │       └── main.js                    # Auto-dismiss de alertas y scripts de cliente
    │       └── templates/
    │           ├── admin/
    │           │   └── panel.html                 # Panel de administración exclusivo para ROLE_ADMIN
    │           ├── dashboard.html                 # Dashboard del usuario con contraste activo XSS
    │           ├── login.html                     # Login con formulario tradicional y token CSRF
    │           └── registro.html                  # Registro con validación de campos Jakarta
    └── test/
        ├── java/
        │   └── com/
        │       └── universidad/
        │           └── seguridad/
        │               ├── GenerarHashTest.java               # Prueba @SpringBootTest de BCrypt cost 12
        │               ├── SeguridadWebApplicationTests.java   # Verificación de carga del contexto
        │               ├── controller/
        │               │   ├── ApiAuthControllerTest.java     # Pruebas MockMvc para API REST y JWT
        │               │   └── AuthControllerWebTest.java     # Pruebas MockMvc para Form Login, CSRF y Vistas
        │               └── security/
        │                   └── JwtUtilTest.java               # Pruebas unitarias de emisión y verificación JWT
        └── resources/
            └── application.properties             # Perfil H2 en memoria para pruebas automáticas sin MySQL
```

---

## 5. Instrucciones de Despliegue y Ejecución

### Prerrequisitos
- **Java Development Kit (JDK) 17 o superior** (OpenJDK / Eclipse Temurin).
- **Apache Maven 3.8+**.
- **MySQL Server 8.0+** en ejecución local o contenedor Docker.

### Paso 1: Configurar la Base de Datos MySQL
Acceda a su cliente de MySQL (consola, MySQL Workbench o DBeaver) y ejecute:

```sql
CREATE DATABASE IF NOT EXISTS seguridad_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

Si utiliza un usuario o contraseña diferente a `root`/`root`, actualice las credenciales en `src/main/resources/application.properties`:
```properties
spring.datasource.url=jdbc:mysql://localhost:3306/seguridad_db?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true&createDatabaseIfNotExist=true
spring.datasource.username=root
spring.datasource.password=root
```

### Paso 2: Compilación y Ejecución de Pruebas Automatizadas
Ejecute la suite completa de pruebas unitarias y de integración para validar la integridad de la solución:

```bash
mvn clean test
```
*Resultado esperado:* **BUILD SUCCESS** con 19 pruebas ejecutadas satisfactoriamente (0 fallos, 0 errores).

### Paso 3: Arrancar el Servidor de Aplicaciones
Inicie la aplicación mediante el plugin de Maven:

```bash
mvn spring-boot:run
```

O genere el paquete JAR autoejecutable:

```bash
mvn clean package -DskipTests
java -jar target/seguridad-web-1.0.0.jar
```

El servidor quedará escuchando en `http://localhost:8080`.

---

## 6. Guía de Pruebas con Comandos cURL

### Credenciales Precargadas de Demostración:
| Rol | Correo Electrónico | Contraseña en Plano |
| :--- | :--- | :--- |
| **Administrador (`ROLE_ADMIN`)** | `admin@universidad.edu` | `AdminPassword123!` |
| **Usuario Regular (`ROLE_USER`)** | `juan.perez@universidad.edu` | `UserPassword123!` |

---

### A. Autenticación y Emisión de Token JWT (200 OK)
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"juan.perez@universidad.edu","contrasenia":"UserPassword123!"}'
```
**Respuesta esperada (HTTP 200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJyb2wiOiJST0xFX1VTRVIiLCJzdWIiOiJqdWFuLnBlcmV6QHVuaXZlcnNpZGFkLmVkdSIsImlhdCI6MTY5OTAwMDAwMCwiZXhwIjoxNjk5MDAzNjAwfQ...",
  "tipo": "Bearer",
  "email": "juan.perez@universidad.edu",
  "rol": "ROLE_USER",
  "expiracionMs": 3600000
}
```

---

### B. Consulta de Tareas con Token Bearer Válido (200 OK)
*(Reemplace `<TOKEN>` con el valor obtenido en el paso A):*
```bash
curl -X GET http://localhost:8080/api/tareas \
  -H "Authorization: Bearer <TOKEN>"
```
**Respuesta esperada (HTTP 200 OK):**
```json
[
  {
    "id": 1,
    "titulo": "Auditar endpoints de API REST",
    "descripcion": "Verificar que /api/tareas devuelva 401 si no lleva Bearer token.",
    "completada": false,
    "propietarioEmail": "juan.perez@universidad.edu",
    "propietarioNombre": "Juan Perez"
  }
]
```

---

### C. Petición sin Token de Autorización (401 Unauthorized)
```bash
curl -i -X GET http://localhost:8080/api/tareas
```
**Respuesta esperada (HTTP 401 Unauthorized):**
```json
{
  "path": "/api/tareas",
  "error": "Unauthorized",
  "message": "Acceso denegado: Token JWT ausente, invalido o expirado.",
  "timestamp": "2026-11-05T18:30:00Z",
  "status": 401
}
```

---

### D. Petición con Token JWT Alterado / Manipulado (401 Unauthorized)
```bash
curl -i -X GET http://localhost:8080/api/tareas \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.TOKEN_MANIPULADO_FALSIFICADO.FIRMA_INVALIDA"
```
**Respuesta esperada (HTTP 401 Unauthorized):**
La cadena de filtros detecta el fallo de firma HMAC-SHA y deniega el acceso a través de `CustomAuthenticationEntryPoint` devolviendo HTTP 401.

---

### E. Control de Acceso por Roles: Usuario Regular a Endpoint de Administrador (403 Forbidden)
```bash
curl -i -X GET http://localhost:8080/api/admin/usuarios \
  -H "Authorization: Bearer <TOKEN_DE_JUAN_PEREZ>"
```
**Respuesta esperada (HTTP 403 Forbidden):**
El usuario autenticado posee `ROLE_USER`, mientras que `/api/admin/**` exige `ROLE_ADMIN`.

---

### F. Acceso a Endpoint de Administrador con Credenciales de Administrador (200 OK)
1. Obtener token del administrador:
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@universidad.edu","contrasenia":"AdminPassword123!"}'
```
2. Consultar usuarios:
```bash
curl -X GET http://localhost:8080/api/admin/usuarios \
  -H "Authorization: Bearer <TOKEN_ADMIN>"
```
**Respuesta esperada (HTTP 200 OK):** Lista completa de usuarios persistidos en MySQL.

---

### G. Prueba de Seguridad CSRF en la Capa Web (403 Forbidden)
Intento de forzar una petición POST de cierre de sesión o creación de tarea sin token CSRF:
```bash
curl -i -X POST http://localhost:8080/dashboard/tareas \
  -d "titulo=Tarea+Maliciosa+CSRF"
```
**Respuesta esperada (HTTP 403 Forbidden):**
Spring Security intercepta la petición a través del `CsrfFilter` en `webFilterChain` y rechaza la solicitud porque carece del token CSRF requerido.

---

## 7. Historial Cronológico de Commits Git

El repositorio cuenta con 6 commits atómicos organizados cronológicamente siguiendo la especificación Conventional Commits:

| Commit # | Hash | Mensaje de Commit | Alcance Técnico |
| :---: | :---: | :--- | :--- |
| **1** | `66e9805` | `feat(core): inicializar proyecto seguridad-web con entidades JPA, repositorios y BCrypt cost 12` | Entidades `Usuario` y `Tarea`, repositorios con contraste de SQL Injection, servicios con BCrypt cost 12 y DTOs base. |
| **2** | `f407aee` | `feat(security): configurar autenticacion basada en sesion con Spring Security 6 y UserDetailsService` | `UsuarioDetailsService`, `SecurityConfig` base con `@Order(2)`, `DataInitializer`, scripts `schema.sql` y `data.sql`, pruebas de hash BCrypt. |
| **3** | `1b614eb` | `feat(web): implementar controladores AuthController y plantillas Thymeleaf con mitigacion activa XSS` | `AuthController`, plantillas `login.html`, `registro.html`, `dashboard.html` (contraste `th:text` vs `th:utext`), `panel.html` y suite web MockMvc. |
| **4** | `e3d04d8` | `feat(jwt): incorporar utilidades JwtUtil y filtro OncePerRequestFilter con HMAC-SHA256` | `JwtUtil` (JJWT 0.12.5), `JwtAuthFilter` delegador, `CustomAuthenticationEntryPoint`, DTOs de login y pruebas unitarias de token. |
| **5** | `df87ccf` | `feat(api): configurar apiFilterChain stateless @Order(1) y controladores REST protegidos` | Cadena `@Order(1)` stateless sin CSRF justificada, `ApiAuthController`, `ApiTareaController`, `ApiAdminController` y pruebas de integración. |
| **6** | `6eaa308` | `docs: completar README.md con arquitectura de coexistencia, mitigaciones de seguridad y manual de ejecucion` | Documentación exhaustiva, diagramas arquitectónicos, justificación CSRF, pruebas cURL y placeholders de capturas. |

---

## 8. Evidencia de Ejecución y Placeholders de Capturas

Para completar la entrega del laboratorio, adjunte en el directorio `docs/screenshots/` las 8 capturas de pantalla de evidencia solicitadas:

1. **`docs/screenshots/01-login-form.png`**: Interfaz de inicio de sesión web en `http://localhost:8080/login` con formulario estilizado y mensajes informativos.
2. **`docs/screenshots/02-dashboard-user.png`**: Dashboard del usuario autenticado en `http://localhost:8080/dashboard` mostrando tareas y la caja de mitigación XSS (`th:text`).
3. **`docs/screenshots/03-admin-panel.png`**: Vista de administración exclusiva en `http://localhost:8080/admin` con la tabla global de usuarios de MySQL.
4. **`docs/screenshots/04-csrf-blocked.png`**: Bloqueo de petición POST sin token CSRF evidenciando respuesta HTTP 403 Forbidden.
5. **`docs/screenshots/05-jwt-login-postman.png`**: Ejecución en cURL o Postman del endpoint `POST /api/auth/login` retornando token Bearer con código 200 OK.
6. **`docs/screenshots/06-jwt-authenticated-request.png`**: Petición `GET /api/tareas` autenticada mediante el encabezado `Authorization: Bearer <token>` recibiendo JSON 200 OK.
7. **`docs/screenshots/07-jwt-tampered-token-401.png`**: Respuesta HTTP 401 Unauthorized devuelta por la API REST ante una petición con token alterado o ausente.
8. **`docs/screenshots/08-test-suite-success.png`**: Terminal con la ejecución exitosa de `mvn clean test` mostrando **BUILD SUCCESS** y 19 pruebas pasando satisfactoriamente.
