package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.UsuarioDTO;
import com.universidad.seguridad.service.UsuarioService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controlador REST restringido exclusivamente para administradores (ROLE_ADMIN).
 * Protegido a nivel de ruta (/api/admin/**) en SecurityConfig y anotaciones @PreAuthorize.
 */
@RestController
@RequestMapping("/api/admin")
public class ApiAdminController {

    private final UsuarioService usuarioService;

    public ApiAdminController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
    }

    /**
     * Lista todos los usuarios registrados en el sistema.
     */
    @GetMapping("/usuarios")
    public ResponseEntity<List<UsuarioDTO>> listarUsuarios() {
        return ResponseEntity.ok(usuarioService.listarTodos());
    }

    /**
     * Metricas del sistema para auditoria administrativa.
     */
    @GetMapping("/metricas")
    public ResponseEntity<Map<String, Object>> obtenerMetricas() {
        List<UsuarioDTO> usuarios = usuarioService.listarTodos();
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalUsuarios", usuarios.size());
        stats.put("usuariosActivos", usuarios.stream().filter(UsuarioDTO::activo).count());
        stats.put("administradores", usuarios.stream().filter(u -> "ROLE_ADMIN".equals(u.rol())).count());
        stats.put("estado", "OPERATIVO");
        return ResponseEntity.ok(stats);
    }
}
