package com.universidad.seguridad.config;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Inicializador de datos para garantizar la existencia de usuarios base
 * (Administrador y Usuario regular) y tareas de ejemplo en el arranque de la aplicacion.
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final UsuarioRepository usuarioRepository;
    private final TareaRepository tareaRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UsuarioRepository usuarioRepository,
                           TareaRepository tareaRepository,
                           PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.tareaRepository = tareaRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        // 1. Inicializar Usuario Administrador
        if (!usuarioRepository.existsByEmail("admin@universidad.edu")) {
            Usuario admin = new Usuario();
            admin.setNombre("Administrador Principal");
            admin.setEmail("admin@universidad.edu");
            // Contrasena hasheada con BCrypt cost 12: 'AdminPassword123!'
            admin.setContrasenia(passwordEncoder.encode("AdminPassword123!"));
            admin.setRol("ROLE_ADMIN");
            admin.setActivo(true);
            usuarioRepository.save(admin);
            log.info(">>> Usuario Administrador creado: admin@universidad.edu (Password: AdminPassword123!)");
        }

        // 2. Inicializar Usuario Regular de demostracion
        if (!usuarioRepository.existsByEmail("juan.perez@universidad.edu")) {
            Usuario user = new Usuario();
            user.setNombre("Juan Perez");
            user.setEmail("juan.perez@universidad.edu");
            // Contrasena hasheada con BCrypt cost 12: 'UserPassword123!'
            user.setContrasenia(passwordEncoder.encode("UserPassword123!"));
            user.setRol("ROLE_USER");
            user.setActivo(true);
            usuarioRepository.save(user);
            log.info(">>> Usuario Regular creado: juan.perez@universidad.edu (Password: UserPassword123!)");

            // Tareas iniciales para el usuario
            Tarea t1 = new Tarea("Auditar endpoints de API REST", "Verificar que /api/tareas devuelva 401 si no lleva Bearer token.", user, false);
            Tarea t2 = new Tarea("Revisar mitigacion XSS en Thymeleaf", "Comprobar que th:text escape etiquetas html <script>.", user, true);
            tareaRepository.save(t1);
            tareaRepository.save(t2);
            log.info(">>> Tareas de ejemplo inicializadas para Juan Perez.");
        }
    }
}
