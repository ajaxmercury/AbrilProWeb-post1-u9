package com.universidad.seguridad.service;

import com.universidad.seguridad.dto.RegistroDTO;
import com.universidad.seguridad.dto.UsuarioDTO;
import com.universidad.seguridad.model.Usuario;
import java.util.List;
import java.util.Optional;

/**
 * Contrato de servicio para la gestion de usuarios, registro con BCrypt y control de accesos.
 */
public interface UsuarioService {

    /**
     * Registra un nuevo usuario en la base de datos aplicando hash BCrypt con cost 12,
     * asignando el rol por defecto ROLE_USER y activando la cuenta.
     * @param registroDTO datos del formulario de registro.
     * @return usuario registrado persistido.
     */
    Usuario registrarUsuario(RegistroDTO registroDTO);

    /**
     * Registra un usuario directamente (util para scripts y pruebas).
     * @param usuario entidad a persistir con contrasena ya hasheada o a hashear.
     * @return usuario persistido.
     */
    Usuario guardarUsuario(Usuario usuario);

    /**
     * Lista todos los usuarios registrados en el sistema.
     * Exclusivo para administradores mediante verificacion a nivel de metodo @PreAuthorize("hasRole('ADMIN')").
     * @return lista de DTOs de usuarios.
     */
    List<UsuarioDTO> listarTodos();

    /**
     * Busca un usuario por correo electronico.
     * @param email correo a buscar.
     * @return Optional con el usuario si fue hallado.
     */
    Optional<Usuario> buscarPorEmail(String email);

    /**
     * Comprueba si un correo electronico ya esta registrado.
     * @param email correo a verificar.
     * @return true si existe.
     */
    boolean existePorEmail(String email);
}
