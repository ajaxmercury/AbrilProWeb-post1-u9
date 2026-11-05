package com.universidad.seguridad.config;

import com.universidad.seguridad.security.CustomAuthenticationEntryPoint;
import com.universidad.seguridad.security.JwtAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuracion integral de Spring Security 6 y Spring Boot 3.2.x.
 * Implementa una arquitectura dual de seguridad con coexistencia armonica de:
 * 1. Cadena de filtros Stateless con JWT (@Order(1)) para la API REST (/api/**).
 * 2. Cadena de filtros Stateful con Sesion HTTP y CSRF activo (@Order(2)) para vistas Thymeleaf (/**).
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    public SecurityConfig(JwtAuthFilter jwtAuthFilter,
                          CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
    }

    /**
     * =========================================================================================
     * CADENA 1: API REST STATELESS CON JWT (@Order(1))
     * Intercepta unicamente solicitudes hacia '/api/**'.
     * =========================================================================================
     * JUSTIFICACION TECNICA DE DESHABILITAR CSRF:
     * El ataque Cross-Site Request Forgery (CSRF) explota la transmision automatica que realiza el
     * navegador web de cookies de sesion (como JSESSIONID) en peticiones de origen cruzado.
     * En nuestra API REST Stateless (/api/**):
     * 1. No se almacena sesion en el servidor (SessionCreationPolicy.STATELESS).
     * 2. No se utilizan cookies para autenticacion ni autorizacion.
     * 3. La autenticacion se realiza exclusivamente mediante el encabezado 'Authorization: Bearer <token>',
     *    el cual no es transmitido automaticamente por los navegadores en peticiones cross-site,
     *    sino que requiere manipulacion explicita mediante JavaScript en el cliente.
     * Por lo tanto, el vector de ataque CSRF no existe en este contexto y deshabilitar CSRF aqui
     * previene errores innecesarios y optimiza el rendimiento.
     * =========================================================================================
     */
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/login", "/api/auth/registro").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(customAuthenticationEntryPoint))
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * =========================================================================================
     * CADENA 2: APLICACION WEB CON SESION TRADICIONAL Y FORM LOGIN (@Order(2))
     * Intercepta todas las demas solicitudes ('/**').
     * =========================================================================================
     * JUSTIFICACION TECNICA DE MANTENER CSRF ACTIVO:
     * Para las vistas web renderizadas con Thymeleaf, la autenticacion reside en una cookie
     * de sesion (JSESSIONID). Si un usuario autenticado visita un sitio malicioso, este ultimo
     * podria forzar envios de formularios POST hacia nuestra aplicacion utilizando la sesion
     * activa del usuario. El filtro CSRF inyecta y exige un token criptografico sincronizado
     * (Synchronizer Token Pattern) en cada peticion mutativa (POST/PUT/DELETE), impidiendo
     * completamente cualquier ataque de falsificacion de peticiones entre sitios.
     * =========================================================================================
     */
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/**")
                .csrf(Customizer.withDefaults()) // CSRF ACTIVO OBLIGATORIO PARA VISTAS BASADAS EN SESION/COOKIES
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/registro", "/css/**", "/js/**", "/images/**", "/error").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/dashboard", true)
                        .failureUrl("/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));

        return http.build();
    }

    /**
     * Codificador de contrasenas BCrypt configurado con costo 12 (4096 rondas de key stretching).
     * El costo 12 ofrece un equilibrio optimo entre alta resistencia a fuerza bruta y rendimiento.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Expone el AuthenticationManager de Spring Security para ser utilizado
     * tanto por el flujo tradicional de login como por el controlador REST de login (/api/auth/login).
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
