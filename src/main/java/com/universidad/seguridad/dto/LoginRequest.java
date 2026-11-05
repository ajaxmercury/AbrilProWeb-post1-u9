package com.universidad.seguridad.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Record que representa la solicitud de autenticacion para la API REST.
 */
public record LoginRequest(
        @NotBlank(message = "El correo electronico es obligatorio")
        @Email(message = "Formato de correo electronico invalido")
        String email,

        @NotBlank(message = "La contrasena es obligatoria")
        String contrasenia
) {
}
