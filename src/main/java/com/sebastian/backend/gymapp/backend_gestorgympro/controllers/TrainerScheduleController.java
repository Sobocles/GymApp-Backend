package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAvailabilityRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerAvailability;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.GroupClassService;
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

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/trainer-schedule")
public class TrainerScheduleController {



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

    @Autowired
    private TrainerScheduleService trainerScheduleService;

    @Autowired
    private GroupClassService groupClassService;

    @Autowired
    private BookingRepository bookingRepository; 


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
    
        List<TimeSlotDTO> slots = trainerScheduleService.getWeeklySlotsForTrainer(trainerId);
        System.out.println("Slots generados para el entrenador " + trainerId + ": " + slots);
    
        return ResponseEntity.ok(slots);
    }
    
    @PostMapping("/book")
    @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
    public ResponseEntity<?> bookSlot(@RequestParam Long trainerId,
                                      @RequestParam String slotStart,
                                      Authentication authentication) {
        String currentUserEmail = authentication.getName();
    
        Optional<User> userOpt = userService.findByEmail(currentUserEmail);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
        }
    
        User user = userOpt.get();
    
        try {
            LocalDateTime slotDateTime = LocalDateTime.parse(slotStart);
            boolean success = trainerScheduleService.bookSlot(user.getId(), trainerId, slotDateTime);
    
            if (success) {
                return ResponseEntity.ok("Reserva exitosa");
            } else {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("El horario ya ha sido reservado.");
            }
    
        } catch (IllegalStateException e) {
            System.out.println("Reserva fallida: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                        "error", "Reserva no permitida",
                        "message", e.getMessage()  // Envía el mensaje exacto
                    ));
        } catch (DateTimeParseException e) {
            return ResponseEntity.badRequest().body("Formato de fecha y hora inválido");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                        "error", "Error inesperado",
                        "message", "Ocurrió un error al procesar la reserva"
                    ));
        }
    }
    
    @PostMapping("/{trainerId}/availability")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createTrainerAvailability(@PathVariable Long trainerId,
                                                       @RequestBody TrainerAvailabilityRequest request) {
        PersonalTrainer trainer = trainerService.findPersonalTrainerById(trainerId)
                .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));
    
        TrainerAvailability availability = new TrainerAvailability();
        availability.setTrainer(trainer);
        availability.setDay(request.getDay());
        availability.setStartTime(request.getStartTime());
        availability.setEndTime(request.getEndTime());

        trainerAvailabilityRepository.save(availability);

        return ResponseEntity.status(HttpStatus.CREATED).body("Disponibilidad creada exitosamente");
    }

    @GetMapping("/{trainerId}/calendar")
    public ResponseEntity<?> getTrainerCalendar(@PathVariable Long trainerId, Authentication authentication) {
        List<CalendarEventDTO> events = trainerScheduleService.getTrainerCalendar(trainerId);
        return ResponseEntity.ok(events);
    }



            // Nuevo endpoint para obtener entrenadores disponibles
            @GetMapping("/all-available")
            @PreAuthorize("hasAnyRole('USER', 'TRAINER', 'ADMIN')")
            public ResponseEntity<List<PersonalTrainerDto>> getAllAvailableTrainers() {
                // Llamada al servicio que obtiene todos los entrenadores disponibles
                List<PersonalTrainerDto> availableTrainers = trainerService.getAvailableTrainers();
                return ResponseEntity.ok(availableTrainers);
            }

    @PostMapping("/{classId}/assign-trainer")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> assignTrainerToClass(@PathVariable Long classId,
                                                @RequestParam Long trainerId) {
        GroupClass groupClass = groupClassService.findById(classId)
                .orElseThrow(() -> new IllegalArgumentException("Clase no encontrada con ID: " + classId));

        PersonalTrainer trainer = trainerService.findPersonalTrainerById(trainerId)
                .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));

        // Validar disponibilidad del entrenador para ese horario
        boolean hasOverlap = bookingRepository.hasOverlappingBookings(trainerId, groupClass.getStartTime(), groupClass.getEndTime());
        boolean isAvailableForClass = trainerAvailabilityRepository.isTrainerAvailable(
            trainerId,
            groupClass.getStartTime().toLocalDate(),
            groupClass.getStartTime().toLocalTime(),
            groupClass.getEndTime().toLocalTime()
        );

        if (hasOverlap || !isAvailableForClass) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("El entrenador no está disponible en el horario de esta clase.");
        }

        // Asignar entrenador a la clase
        groupClass.setAssignedTrainer(trainer);
        groupClassService.save(groupClass); // Actualizar la clase con el entrenador asignado

        return ResponseEntity.ok("Entrenador asignado a la clase con éxito.");
    }

            
 
}
