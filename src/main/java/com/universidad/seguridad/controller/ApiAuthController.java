package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.LoginRequest;
import com.universidad.seguridad.dto.LoginResponse;
import com.universidad.seguridad.dto.RegistroDTO;
import com.universidad.seguridad.dto.UsuarioDTO;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.security.JwtUtil;
import com.universidad.seguridad.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controlador REST para autenticacion y emision de tokens JWT.
 * Reutiliza el AuthenticationManager central de Spring Security.
 */
@RestController
@RequestMapping("/api/auth")
public class ApiAuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UsuarioService usuarioService;

    public ApiAuthController(AuthenticationManager authenticationManager,
                             JwtUtil jwtUtil,
                             UsuarioService usuarioService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.usuarioService = usuarioService;
    }

    /**
     * Endpoint publico para inicio de sesion en la API REST.
     * Recibe credenciales, autentica contra MySQL mediante AuthenticationManager y emite JWT.
     *
     * @param request credenciales del usuario (email y contrasena).
     * @return token JWT firmado y metadatos del usuario autenticado.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.email().trim().toLowerCase(),
                            request.contrasenia()
                    )
            );

            String email = authentication.getName();
            String rol = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .findFirst()
                    .orElse("ROLE_USER");

            String token = jwtUtil.generarToken(email, rol);

            LoginResponse response = new LoginResponse(
                    token,
                    "Bearer",
                    email,
                    rol,
                    jwtUtil.getExpirationMs()
            );

            return ResponseEntity.ok(response);

        } catch (BadCredentialsException ex) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", HttpStatus.UNAUTHORIZED.value());
            error.put("error", "Unauthorized");
            error.put("message", "Credenciales invalidas: correo o contrasena incorrectos.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    /**
     * Endpoint opcional para registro directo de nuevos usuarios via API REST.
     */
    @PostMapping("/registro")
    public ResponseEntity<?> registrar(@Valid @RequestBody RegistroDTO registroDTO) {
        try {
            Usuario usuario = usuarioService.registrarUsuario(registroDTO);
            return ResponseEntity.status(HttpStatus.CREATED).body(UsuarioDTO.fromEntity(usuario));
        } catch (IllegalArgumentException ex) {
            Map<String, String> error = new HashMap<>();
            error.put("error", ex.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
}
