package com.universidad.seguridad.controller;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerWebTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("GET /login publico debe retornar vista login con HTTP 200")
    void testGetLoginPage() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    @DisplayName("GET /dashboard sin sesion debe redirigir a /login")
    void testDashboardSinSesionRedirigeLogin() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("Form login con credenciales correctas redirige a /dashboard")
    void testFormLoginExitoso() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "admin@universidad.edu")
                        .password("password", "AdminPassword123!"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"));
    }

    @Test
    @DisplayName("Form login con credenciales incorrectas redirige a /login?error=true")
    void testFormLoginFallido() throws Exception {
        mockMvc.perform(formLogin("/login")
                        .user("username", "admin@universidad.edu")
                        .password("password", "claveIncorrecta"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error=true"));
    }

    @Test
    @DisplayName("POST sin token CSRF en web debe retornar 403 Forbidden")
    void testPostSinCsrfRetorna403() throws Exception {
        mockMvc.perform(post("/dashboard/tareas")
                        .param("titulo", "Tarea de Ataque CSRF"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "juan.perez@universidad.edu", roles = {"USER"})
    @DisplayName("GET /admin con ROLE_USER debe retornar 403 Forbidden")
    void testAccesoAdminConRolUserRetorna403() throws Exception {
        mockMvc.perform(get("/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin@universidad.edu", roles = {"ADMIN"})
    @DisplayName("GET /admin con ROLE_ADMIN debe retornar vista admin/panel con 200 OK")
    void testAccesoAdminConRolAdminRetorna200() throws Exception {
        mockMvc.perform(get("/admin"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/panel"));
    }

    @Test
    @WithMockUser(username = "juan.perez@universidad.edu")
    @DisplayName("Logout exitoso invalida la sesion y borra cookie JSESSIONID")
    void testLogoutInvalidaSesion() throws Exception {
        mockMvc.perform(logout("/logout"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout=true"));
    }
}
