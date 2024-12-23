package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.CreateGroupClassRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.GroupClassBookingService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.GroupClassService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/group-classes")
public class GroupClassController {

    @Autowired
    private GroupClassService groupClassService;

    @Autowired
    private GroupClassBookingService groupClassBookingService;

    @Autowired
    private UserService userService;

    /**
     * Crear una nueva clase grupal (solo ADMIN)
     */
    @PostMapping("/create")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createClass(@RequestBody CreateGroupClassRequest request) {
        GroupClass gc = groupClassService.createGroupClass(
            request.getClassName(), 
            request.getStartTime(), 
            request.getEndTime(), 
            request.getMaxParticipants()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(gc);
    }
    

    /**
     * Asignar un entrenador a la clase grupal (solo ADMIN)
     */
    @PostMapping("/{classId}/assign-trainer")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> assignTrainer(@PathVariable Long classId, @RequestParam Long trainerId) {
        groupClassService.assignTrainerToClass(classId, trainerId);
        return ResponseEntity.ok("Entrenador asignado a la clase");
    }

    /**
     * Listar clases disponibles para el usuario
     * Aquí filtramos solo las clases visibles: que no hayan empezado, que estén en el rango de reserva, y que no estén llenas.
     */
    @GetMapping("/available")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'TRAINER')")
    public ResponseEntity<?> listAvailableClasses() {
        List<GroupClass> futureClasses = groupClassService.findFutureClasses();
        LocalDateTime now = LocalDateTime.now();
        List<GroupClass> filtered = futureClasses.stream()
            .filter(gc -> {
                // 12 horas antes y 1 hora antes del inicio
                LocalDateTime earliest = gc.getStartTime().minusHours(12);
                LocalDateTime latest = gc.getStartTime().minusHours(1);
                // La clase debe estar dentro del rango actual de reserva y no iniciada
                return now.isAfter(earliest) && now.isBefore(latest);
            })
            .toList();
        return ResponseEntity.ok(filtered);
    }

    /**
     * Reservar una clase grupal (USER con plan o USER con trainer)
     */
    @PostMapping("/{classId}/book")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'TRAINER')")
    public ResponseEntity<?> bookClass(@PathVariable Long classId, Authentication auth) {
        String email = auth.getName();
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
        }
        User user = userOpt.get();

        try {
            groupClassBookingService.bookClass(user, classId);
            return ResponseEntity.ok("Clase reservada con éxito");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
