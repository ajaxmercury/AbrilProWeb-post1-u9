package com.universidad.seguridad.repository;

import com.universidad.seguridad.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repositorio Spring Data JPA para la entidad Usuario.
 */
@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {

    /**
     * Busca un usuario por su direccion de correo electronico unica.
     * @param email correo electronico a buscar.
     * @return Optional con el usuario si existe.
     */
    Optional<Usuario> findByEmail(String email);

    /**
     * Verifica la existencia previa de un correo electronico para validaciones de registro.
     * @param email correo a verificar.
     * @return true si ya se encuentra registrado, false en caso contrario.
     */
    boolean existsByEmail(String email);
}
