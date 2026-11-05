package com.universidad.seguridad.service;

import com.universidad.seguridad.dto.RegistroDTO;
import com.universidad.seguridad.dto.UsuarioDTO;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.UsuarioRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Implementacion del servicio de usuarios.
 * Aplica codificacion BCrypt con factor de costo 12 para maxima resistencia ante ataques de fuerza bruta.
 */
@Service
public class UsuarioServiceImpl implements UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;

    public UsuarioServiceImpl(UsuarioRepository usuarioRepository, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public Usuario registrarUsuario(RegistroDTO registroDTO) {
        if (usuarioRepository.existsByEmail(registroDTO.getEmail())) {
            throw new IllegalArgumentException("El correo electronico ya se encuentra registrado: " + registroDTO.getEmail());
        }

        if (!registroDTO.getContrasenia().equals(registroDTO.getConfirmarContrasenia())) {
            throw new IllegalArgumentException("Las contrasenas proporcionadas no coinciden.");
        }

        // Hashing BCrypt con factor de costo 12 (2^12 = 4096 rondas de key stretching)
        String contraseniaHasheada = passwordEncoder.encode(registroDTO.getContrasenia());

        Usuario nuevoUsuario = new Usuario();
        nuevoUsuario.setNombre(registroDTO.getNombre().trim());
        nuevoUsuario.setEmail(registroDTO.getEmail().trim().toLowerCase());
        nuevoUsuario.setContrasenia(contraseniaHasheada);
        nuevoUsuario.setRol("ROLE_USER"); // Rol por defecto
        nuevoUsuario.setActivo(true);     // Estado activo por defecto

        return usuarioRepository.save(nuevoUsuario);
    }

    @Override
    @Transactional
    public Usuario guardarUsuario(Usuario usuario) {
        // Si la contrasena no viene ya con formato de hash BCrypt ($2a$12$ o similar), se encripta
        if (usuario.getContrasenia() != null && !usuario.getContrasenia().startsWith("$2a$") && !usuario.getContrasenia().startsWith("$2b$")) {
            usuario.setContrasenia(passwordEncoder.encode(usuario.getContrasenia()));
        }
        return usuarioRepository.save(usuario);
    }

    @Override
    @Transactional(readOnly = true)
    @PreAuthorize("hasRole('ADMIN')")
    public List<UsuarioDTO> listarTodos() {
        return usuarioRepository.findAll()
                .stream()
                .map(UsuarioDTO::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<Usuario> buscarPorEmail(String email) {
        return usuarioRepository.findByEmail(email);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existePorEmail(String email) {
        return usuarioRepository.existsByEmail(email);
    }
}
