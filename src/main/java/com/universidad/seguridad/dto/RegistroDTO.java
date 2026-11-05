package com.universidad.seguridad.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Objeto de transferencia de datos para el formulario de registro de usuarios.
 */
public class RegistroDTO {

    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 2, max = 100, message = "El nombre debe contener entre 2 y 100 caracteres")
    private String nombre;

    @NotBlank(message = "El correo electronico es obligatorio")
    @Email(message = "El formato de correo electronico es invalido")
    private String email;

    @NotBlank(message = "La contrasena es obligatoria")
    @Size(min = 6, max = 50, message = "La contrasena debe tener al menos 6 caracteres")
    private String contrasenia;

    @NotBlank(message = "Debe confirmar la contrasena")
    private String confirmarContrasenia;

    public RegistroDTO() {
    }

    public RegistroDTO(String nombre, String email, String contrasenia, String confirmarContrasenia) {
        this.nombre = nombre;
        this.email = email;
        this.contrasenia = contrasenia;
        this.confirmarContrasenia = confirmarContrasenia;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getContrasenia() {
        return contrasenia;
    }

    public void setContrasenia(String contrasenia) {
        this.contrasenia = contrasenia;
    }

    public String getConfirmarContrasenia() {
        return confirmarContrasenia;
    }

    public void setConfirmarContrasenia(String confirmarContrasenia) {
        this.confirmarContrasenia = confirmarContrasenia;
    }
}
