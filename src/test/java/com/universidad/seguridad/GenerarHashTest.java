package com.universidad.seguridad;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Clase de prueba para verificar la generacion de hashes con BCrypt (Cost 12)
 * y corroborar la validez de las credenciales del Administrador.
 */
@SpringBootTest
class GenerarHashTest {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("Debe generar y validar hash BCrypt con costo 12 correctamente")
    void testGenerarYValidarHashCost12() {
        String rawPassword = "AdminPassword123!";

        // Instanciar directamente BCryptPasswordEncoder con cost 12 para comprobacion
        BCryptPasswordEncoder encoderCost12 = new BCryptPasswordEncoder(12);

        String hash1 = encoderCost12.encode(rawPassword);
        String hash2 = encoderCost12.encode(rawPassword);

        System.out.println("=================================================================");
        System.out.println("PRUEBA GENERACION BCRYPT COST 12:");
        System.out.println("Password en plano : " + rawPassword);
        System.out.println("Hash generado 1  : " + hash1);
        System.out.println("Hash generado 2  : " + hash2);
        System.out.println("=================================================================");

        // El prefijo $2a$12$ o $2b$12$ certifica el algoritmo y el costo (12 rondas = 4096 iteraciones)
        assertTrue(hash1.startsWith("$2a$12$") || hash1.startsWith("$2b$12$"), "El hash debe contener el prefijo de costo 12");

        // Dos ejecuciones deben producir hashes distintos debido al salt criptografico aleatorio (salting)
        assertNotEquals(hash1, hash2, "Dos hashes de la misma contrasena deben ser diferentes debido al salt aleatorio");

        // Ambos hashes deben validar exitosamente contra la contrasena en plano
        assertTrue(encoderCost12.matches(rawPassword, hash1), "El hash 1 debe coincidir con la contrasena");
        assertTrue(encoderCost12.matches(rawPassword, hash2), "El hash 2 debe coincidir con la contrasena");

        // El bean inyectado en el contexto de Spring Boot tambien debe validar satisfactoriamente
        assertTrue(passwordEncoder.matches(rawPassword, hash1), "El bean PasswordEncoder debe verificar el hash");
    }
}
