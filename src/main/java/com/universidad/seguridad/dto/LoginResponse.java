package com.universidad.seguridad.dto;

/**
 * Record que representa la respuesta exitosa de autenticacion JWT para la API REST.
 */
public record LoginResponse(
        String token,
        String tipo,
        String email,
        String rol,
        long expiracionMs
) {
    public LoginResponse(String token, String email, String rol, long expiracionMs) {
        this(token, "Bearer", email, rol, expiracionMs);
    }
}
