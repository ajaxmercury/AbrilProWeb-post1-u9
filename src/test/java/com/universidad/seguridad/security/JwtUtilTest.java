package com.universidad.seguridad.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private final String secret = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private final long expirationMs = 3600000; // 1 hora

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil(secret, expirationMs);
    }

    @Test
    @DisplayName("Debe generar token valido y extraer claims de email y rol")
    void testGenerarYExtraerClaims() {
        String email = "admin@universidad.edu";
        String rol = "ROLE_ADMIN";

        String token = jwtUtil.generarToken(email, rol);

        assertNotNull(token);
        assertTrue(jwtUtil.validarToken(token));
        assertEquals(email, jwtUtil.extraerEmail(token));
        assertEquals(rol, jwtUtil.extraerRol(token));
    }

    @Test
    @DisplayName("Debe rechazar token alterado o con firma invalida")
    void testTokenAlteradoInvalido() {
        String token = jwtUtil.generarToken("usuario@universidad.edu", "ROLE_USER");
        // Modificar un caracter del payload
        String tokenAlterado = token.substring(0, token.length() - 5) + "abcde";

        assertFalse(jwtUtil.validarToken(tokenAlterado));
    }

    @Test
    @DisplayName("Debe rechazar token expirado")
    void testTokenExpirado() {
        // JwtUtil con tiempo de expiracion negativo (-1 ms)
        JwtUtil jwtExpiradoUtil = new JwtUtil(secret, -1000);
        String tokenExpirado = jwtExpiradoUtil.generarToken("juan@universidad.edu", "ROLE_USER");

        assertFalse(jwtUtil.validarToken(tokenExpirado));
    }
}
