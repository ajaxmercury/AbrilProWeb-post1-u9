package com.universidad.seguridad.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * Filtro interceptor para la API REST que procesa tokens JWT en cada solicitud HTTP.
 * Extrae el encabezado 'Authorization: Bearer <token>', valida la firma y expiracion,
 * y establece la autenticacion en el SecurityContextHolder.
 * Si el token es nulo o invalido, NO lanza excepciones, permitiendo que la cadena de
 * filtros de Spring Security delegue la denegacion 401 al AuthenticationEntryPoint.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // Si no existe encabezado o no cumple el esquema Bearer, continuar la cadena sin autenticar
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7).trim();

        try {
            if (jwtUtil.validarToken(jwt)) {
                String email = jwtUtil.extraerEmail(jwt);
                String rol = jwtUtil.extraerRol(jwt);

                if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    List<SimpleGrantedAuthority> authorities = Collections.singletonList(
                            new SimpleGrantedAuthority(rol != null ? rol : "ROLE_USER")
                    );

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            email,
                            null,
                            authorities
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.debug("Autenticacion JWT exitosa para usuario: {} con rol: {}", email, rol);
                }
            } else {
                log.warn("Filtro JWT: Token recibido no es valido o ha expirado.");
            }
        } catch (Exception e) {
            // No lanzar la excepcion hacia el cliente; registrar el evento y permitir que Spring Security
            // deniegue el acceso con codigo 401 Unauthorized de forma estandarizada en la cadena
            log.warn("Error durante el procesamiento del token JWT: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
