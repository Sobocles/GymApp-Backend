package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAvailabilityRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerAvailability;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerScheduleService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.impl.SubscriptionServiceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/trainer-schedule")
public class TrainerScheduleController {

    @Autowired
    private TrainerScheduleService scheduleService;

    @Autowired
    private UserService userService;

    @Autowired
    private SubscriptionServiceImpl subscriptionService;

    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
    private TrainerAvailabilityRepository trainerAvailabilityRepository;

    @Autowired
    private TrainerService trainerService;


    @GetMapping("/{trainerId}/weekly-slots")
    @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
    public ResponseEntity<?> getWeeklySlots(@PathVariable Long trainerId, Authentication authentication) {
        String email = authentication.getName();
        System.out.println("Usuario autenticado: " + email);
    
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            System.out.println("Usuario no autenticado.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body("Usuario no autenticado");
        }
    
        User user = userOpt.get();
        System.out.println("Usuario encontrado: " + user.getId() + " - " + user.getEmail());
    
        boolean hasSubscription = subscriptionService.hasActivePlanWithTrainer(user.getId(), trainerId) ||
                                   personalTrainerSubscriptionService.hasActiveTrainerSubscription(user.getId(), trainerId);
        System.out.println("El usuario tiene suscripción activa con el entrenador: " + hasSubscription);
    
        if (!hasSubscription) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("No tienes una suscripción activa para ver los slots semanales de este entrenador.");
        }
    
        List<TimeSlotDTO> slots = scheduleService.getWeeklySlotsForTrainer(trainerId);
        System.out.println("Slots generados para el entrenador " + trainerId + ": " + slots);
    
        return ResponseEntity.ok(slots);
    }
    
    

    @PostMapping("/book")
    @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
    public ResponseEntity<?> bookSlot(@RequestParam Long trainerId,
                                      @RequestParam String slotStart,
                                      Authentication authentication) {
        String currentUserEmail = authentication.getName();

        // Obtener el usuario autenticado
        Optional<User> userOpt = userService.findByEmail(currentUserEmail);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
        }

        User user = userOpt.get();

        // Verificar si el usuario tiene una suscripción activa con este entrenador o un plan que incluye un entrenador
        boolean hasSubscription = subscriptionService.hasActivePlanWithTrainer(user.getId(), trainerId) ||
                                   personalTrainerSubscriptionService.hasActiveTrainerSubscription(user.getId(), trainerId);

        if (!hasSubscription) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("No tienes una suscripción activa para reservar con este entrenador.");
        }

        LocalDateTime slotDateTime;

        // Validar y parsear la fecha y hora de la franja horaria
        try {
            slotDateTime = LocalDateTime.parse(slotStart);
        } catch (DateTimeParseException e) {
            return ResponseEntity.badRequest().body("Formato de fecha y hora inválido");
        }

        // Intentar reservar la franja horaria
        boolean success = scheduleService.bookSlot(user.getId(), trainerId, slotDateTime);
        if (success) {
            return ResponseEntity.ok("Reserva exitosa");
        } else {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Slot ya ocupado");
        }
    }

    @PostMapping("/{trainerId}/availability")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createTrainerAvailability(@PathVariable Long trainerId,
                                                    @RequestBody TrainerAvailabilityRequest request) {
        // Verificar si el entrenador existe
        PersonalTrainer trainer = trainerService.findPersonalTrainerById(trainerId)
        .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));
    
        
        // Crear la nueva disponibilidad
        TrainerAvailability availability = new TrainerAvailability();
        availability.setTrainer(trainer);
        availability.setDay(request.getDay());
        availability.setStartTime(request.getStartTime());
        availability.setEndTime(request.getEndTime());

        trainerAvailabilityRepository.save(availability);

        return ResponseEntity.status(HttpStatus.CREATED).body("Disponibilidad creada exitosamente");
    }
}


