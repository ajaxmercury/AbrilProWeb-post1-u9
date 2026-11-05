package com.universidad.seguridad.repository;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Repositorio Spring Data JPA para la entidad Tarea.
 * Incluye demostracion explicita de mitigacion de SQL Injection mediante consultas parametrizadas.
 */
@Repository
public interface TareaRepository extends JpaRepository<Tarea, Long> {

    /**
     * =========================================================================================
     * ANALISIS Y CONTRASTE DE SEGURIDAD: MITIGACION DE INYECCION SQL (SQL INJECTION)
     * =========================================================================================
     *
     * [VERSION INSEGURA VULNERABLE A SQL INJECTION]:
     * Si se implementara la consulta mediante concatenacion directa de cadenas (por ejemplo,
     * en JDBC tradicional con Statement o JPQL dinamico sin parametros):
     *
     *    // CODIGO VULNERABLE:
     *    // String queryInsegura = "SELECT * FROM tareas WHERE titulo LIKE '%" + texto + "%'";
     *    // Statement stmt = connection.createStatement();
     *    // ResultSet rs = stmt.executeQuery(queryInsegura);
     *
     * IMPACTO DEL ATAQUE:
     * Si un usuario malicioso suministra como 'texto' la carga util:
     *    texto = "' UNION SELECT id, contrasenia, email, rol, nombre FROM usuarios --"
     * o simplemente:
     *    texto = "' OR '1'='1"
     * La consulta concatenada altera la semantica del motor SQL:
     *    SELECT * FROM tareas WHERE titulo LIKE '%' OR '1'='1%'
     * Devolviendo registros de todos los usuarios o exfiltrando las contrasenas hasheadas
     * y datos personales desde la tabla de usuarios, violando la confidencialidad e integridad.
     *
     * [VERSION SEGURA IMPLEMENTADA]:
     * Se utiliza la anotacion @Query con JPQL y parametro con nombre (:texto).
     * Spring Data JPA y Hibernate delegan la ejecucion a un PreparedStatement de JDBC.
     * El motor de base de datos compila previamente el arbol sintactico (AST) y el plan
     * de ejecucion de la consulta antes de enlazar los parametros.
     * De esta forma, cualquier entrada del usuario es tratada estrictamente como un
     * valor escalar (literal de datos) y jamas como codigo SQL ejecutable.
     * =========================================================================================
     */
    @Query("SELECT t FROM Tarea t WHERE t.titulo LIKE %:texto%")
    List<Tarea> buscarPorTitulo(@Param("texto") String texto);

    /**
     * Busca las tareas asociadas a una entidad Usuario propietaria.
     * @param propietario usuario dueno de las tareas.
     * @return lista de tareas pertenecientes a dicho usuario.
     */
    List<Tarea> findByPropietario(Usuario propietario);

    /**
     * Busca tareas por el correo del usuario propietario utilizando relaciones JPA.
     * @param email correo del propietario.
     * @return lista de tareas correspondientes.
     */
    List<Tarea> findByPropietarioEmail(String email);

    /**
     * Busca tareas de un usuario filtrando por coincidencia parcial en el titulo (parametrizada).
     */
    @Query("SELECT t FROM Tarea t WHERE t.propietario.email = :email AND t.titulo LIKE %:texto%")
    List<Tarea> buscarPorPropietarioYTitulo(@Param("email") String email, @Param("texto") String texto);
}
