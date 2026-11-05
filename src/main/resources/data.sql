-- ==============================================================================
-- DML INICIAL: Insercion de usuario administrador con BCrypt (Cost 12)
-- Contrasena en plano para admin: AdminPassword123!
-- Contrasena en plano para user : UserPassword123!
-- ==============================================================================

INSERT INTO usuarios (id, nombre, email, contrasenia, rol, activo)
VALUES (1, 'Administrador Principal', 'admin@universidad.edu',
        '$2a$12$9J5FrvVQlmAOB0nI.bXvmON7a0GqIs1XFpMBSNt/T/WehiOwtHlo2', 'ROLE_ADMIN', TRUE)
ON DUPLICATE KEY UPDATE email=email;

INSERT INTO usuarios (id, nombre, email, contrasenia, rol, activo)
VALUES (2, 'Juan Perez', 'juan.perez@universidad.edu',
        '$2a$12$nnTt.K6ENqnnAXTxjN5QCOxbYh34uMGl0bCdIXWuyIDZmXBKW1vb6', 'ROLE_USER', TRUE)
ON DUPLICATE KEY UPDATE email=email;

INSERT INTO tareas (id, titulo, descripcion, usuario_id, completada)
VALUES (1, 'Auditar endpoints de API REST', 'Verificar que /api/tareas devuelva 401 si no lleva Bearer token.', 2, FALSE)
ON DUPLICATE KEY UPDATE titulo=titulo;

INSERT INTO tareas (id, titulo, descripcion, usuario_id, completada)
VALUES (2, 'Revisar mitigacion XSS en Thymeleaf', 'Comprobar que th:text escape etiquetas html <script>.', 2, TRUE)
ON DUPLICATE KEY UPDATE titulo=titulo;
