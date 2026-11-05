package com.universidad.seguridad.dto;

import com.universidad.seguridad.model.Usuario;

/**
 * DTO para exposicion segura de datos de Usuario (sin exponer contrasena).
 */
public record UsuarioDTO(
        Long id,
        String nombre,
        String email,
        String rol,
        boolean activo
) {
    public static UsuarioDTO fromEntity(Usuario u) {
        return new UsuarioDTO(u.getId(), u.getNombre(), u.getEmail(), u.getRol(), u.isActivo());
    }
}
