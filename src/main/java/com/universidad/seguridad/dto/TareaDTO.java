package com.universidad.seguridad.dto;

import com.universidad.seguridad.model.Tarea;

/**
 * DTO para exposicion y consumo de tareas en la API REST y vistas web.
 */
public record TareaDTO(
        Long id,
        String titulo,
        String descripcion,
        boolean completada,
        String propietarioEmail,
        String propietarioNombre
) {
    public static TareaDTO fromEntity(Tarea t) {
        String pEmail = (t.getPropietario() != null) ? t.getPropietario().getEmail() : null;
        String pNombre = (t.getPropietario() != null) ? t.getPropietario().getNombre() : null;
        return new TareaDTO(
                t.getId(),
                t.getTitulo(),
                t.getDescripcion(),
                t.isCompletada(),
                pEmail,
                pNombre
        );
    }
}
