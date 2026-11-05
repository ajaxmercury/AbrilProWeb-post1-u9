package com.universidad.seguridad.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Componente utilitario para la creacion, firma criptografica y validacion de JSON Web Tokens (JWT).
 * Utiliza algoritmos HMAC-SHA con clave de alta entropia (minimo 256 bits) conforme a JJWT 0.12.5.
 */
@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    private final SecretKey secretKey;
    private final long expirationMs;

    public JwtUtil(
            @Value("${app.jwt.secret:404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970}") String secret,
            @Value("${app.jwt.expiration-ms:3600000}") long expirationMs) {
        // La clave secreta debe tener un minimo de 256 bits (32 bytes) para HMAC-SHA256
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
        this.expirationMs = expirationMs;
    }

    /**
     * Genera un token JWT incluyendo el correo en el subject y el rol como claim personalizado.
     * @param email correo electronico del usuario (subject).
     * @param rol rol de seguridad asignado (ej: ROLE_ADMIN, ROLE_USER).
     * @return cadena compacta del JWT firmada criptograficamente.
     */
    public String generarToken(String email, String rol) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("rol", rol);
        return crearToken(claims, email);
    }

    private String crearToken(Map<String, Object> claims, String subject) {
        Date ahora = new Date();
        Date fechaExpiracion = new Date(ahora.getTime() + expirationMs);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(ahora)
                .expiration(fechaExpiracion)
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Extrae el nombre de usuario (email) contenido en el subject del token.
     * @param token JWT a parsear.
     * @return email del usuario.
     */
    public String extraerEmail(String token) {
        return extraerClaim(token, Claims::getSubject);
    }

    /**
     * Extrae el rol asignado contenido en los claims del token.
     * @param token JWT a parsear.
     * @return rol del usuario.
     */
    public String extraerRol(String token) {
        Claims claims = extraerTodosLosClaims(token);
        return claims != null ? claims.get("rol", String.class) : null;
    }

    /**
     * Extrae la fecha de expiracion del token.
     */
    public Date extraerExpiracion(String token) {
        return extraerClaim(token, Claims::getExpiration);
    }

    public <T> T extraerClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extraerTodosLosClaims(token);
        return claims != null ? claimsResolver.apply(claims) : null;
    }

    public Claims extraerTodosLosClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Error al parsear o validar claims del token JWT: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Valida si el token es estructuralmente valido, no ha expirado y coincide con el usuario.
     * @param token token recibido.
     * @param userDetails detalles del usuario cargado desde UserDetailsService.
     * @return true si es valido.
     */
    public boolean validarToken(String token, UserDetails userDetails) {
        final String email = extraerEmail(token);
        return (email != null && email.equalsIgnoreCase(userDetails.getUsername()) && !estaExpirado(token));
    }

    /**
     * Valida si el token tiene firma correcta y no ha caducado sin necesidad de UserDetails.
     */
    public boolean validarToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.getExpiration().after(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token JWT invalido: {}", e.getMessage());
            return false;
        }
    }

    private boolean estaExpirado(String token) {
        Date expiracion = extraerExpiracion(token);
        return expiracion == null || expiracion.before(new Date());
    }

    public long getExpirationMs() {
        return expirationMs;
    }
}
