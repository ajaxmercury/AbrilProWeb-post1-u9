package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.TareaDTO;
import com.universidad.seguridad.service.TareaService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Controlador REST para la gestion de tareas protegidas mediante JWT.
 * Consume directamente la instancia de Authentication inyectada en el SecurityContext
 * por el filtro JwtAuthFilter tras validar el token Bearer.
 */
@RestController
@RequestMapping("/api/tareas")
public class ApiTareaController {

    private final TareaService tareaService;

    public ApiTareaController(TareaService tareaService) {
        this.tareaService = tareaService;
    }

    /**
     * Obtiene las tareas del usuario autenticado o todas si el usuario posee ROLE_ADMIN.
     * Soporta parametro de consulta opcional 'q' para busqueda parametrizada segura.
     *
     * @param authentication objeto de autenticacion inyectado por Spring Security.
     * @param q filtro opcional de busqueda por titulo.
     * @return lista de tareas en formato DTO.
     */
    @GetMapping
    public ResponseEntity<List<TareaDTO>> obtenerTareas(
            Authentication authentication,
            @RequestParam(name = "q", required = false) String q) {

        String email = authentication.getName();
        boolean esAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

        List<TareaDTO> tareas;

        if (q != null && !q.trim().isEmpty()) {
            if (esAdmin) {
                tareas = tareaService.buscarPorTitulo(q.trim());
            } else {
                tareas = tareaService.buscarPorPropietarioYTitulo(email, q.trim());
            }
        } else {
            if (esAdmin) {
                tareas = tareaService.listarTodas();
            } else {
                tareas = tareaService.listarDe(email);
            }
        }

        return ResponseEntity.ok(tareas);
    }

    public record NuevaTareaRequest(
            @NotBlank(message = "El titulo es obligatorio") String titulo,
            String descripcion
    ) {}

    /**
     * Crea una nueva tarea asociada al usuario autenticado extraido del token JWT.
     */
    @PostMapping
    public ResponseEntity<TareaDTO> crearTarea(
            Authentication authentication,
            @Valid @RequestBody NuevaTareaRequest request) {

        String email = authentication.getName();
        TareaDTO creada = tareaService.crearTarea(request.titulo(), request.descripcion(), email);
        return ResponseEntity.status(HttpStatus.CREATED).body(creada);
    }

    /**
     * Alterna el estado de completada de una tarea verificando pertenencia o rol de administrador.
     */
    @PatchMapping("/{id}/toggle")
    public ResponseEntity<TareaDTO> alternarCompletada(
            Authentication authentication,
            @PathVariable Long id) {

        String email = authentication.getName();
        TareaDTO actualizada = tareaService.alternarCompletada(id, email);
        return ResponseEntity.ok(actualizada);
    }
}
