package com.universidad.seguridad.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.universidad.seguridad.dto.LoginRequest;
import com.universidad.seguridad.security.JwtUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ApiAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtUtil jwtUtil;

    @Test
    @DisplayName("POST /api/auth/login con credenciales validas retorna 200 y token JWT")
    void testLoginExitoso() throws Exception {
        LoginRequest request = new LoginRequest("admin@universidad.edu", "AdminPassword123!");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isString())
                .andExpect(jsonPath("$.tipo").value("Bearer"))
                .andExpect(jsonPath("$.email").value("admin@universidad.edu"))
                .andExpect(jsonPath("$.rol").value("ROLE_ADMIN"));
    }

    @Test
    @DisplayName("POST /api/auth/login con credenciales invalidas retorna 401 Unauthorized")
    void testLoginInvalido() throws Exception {
        LoginRequest request = new LoginRequest("admin@universidad.edu", "ContraseniaErronea");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    @DisplayName("GET /api/tareas sin token Bearer retorna 401 Unauthorized")
    void testGetTareasSinTokenRetorna401() throws Exception {
        mockMvc.perform(get("/api/tareas"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("GET /api/tareas con token Bearer valido retorna 200 OK y lista de tareas")
    void testGetTareasConTokenValidoRetorna200() throws Exception {
        String token = jwtUtil.generarToken("juan.perez@universidad.edu", "ROLE_USER");

        mockMvc.perform(get("/api/tareas")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @DisplayName("GET /api/admin/usuarios con rol ROLE_USER retorna 403 Forbidden")
    void testGetAdminConRolUsuarioRetorna403() throws Exception {
        String tokenUser = jwtUtil.generarToken("juan.perez@universidad.edu", "ROLE_USER");

        mockMvc.perform(get("/api/admin/usuarios")
                        .header("Authorization", "Bearer " + tokenUser))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /api/admin/usuarios con rol ROLE_ADMIN retorna 200 OK")
    void testGetAdminConRolAdminRetorna200() throws Exception {
        String tokenAdmin = jwtUtil.generarToken("admin@universidad.edu", "ROLE_ADMIN");

        mockMvc.perform(get("/api/admin/usuarios")
                        .header("Authorization", "Bearer " + tokenAdmin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }
}
