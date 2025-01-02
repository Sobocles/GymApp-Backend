package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PersonalTrainerDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TrainerAvailabilityRequest;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;
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
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
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
        System.out.println("=== Controller GET /trainer-schedule/" + trainerId + "/weekly-slots ===");
        String email = authentication.getName();
        System.out.println("Usuario autenticado: " + email);
    
        Optional<User> userOpt = userService.findByEmail(email);
        if (userOpt.isEmpty()) {
            System.out.println("Usuario no autenticado, devolviendo 401");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no autenticado");
        }
    
        User user = userOpt.get();
        System.out.println("User ID: " + user.getId());
    
        // Lógica de ver si tiene suscripción
        boolean hasSubscription = subscriptionService.hasActivePlanWithTrainer(user.getId(), trainerId)
            || personalTrainerSubscriptionService.hasActiveTrainerSubscription(user.getId(), trainerId);
        System.out.println("¿Tiene suscripción activa con el trainer " + trainerId + "? " + hasSubscription);
    
        if (!hasSubscription) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                 .body("No tienes una suscripción activa para ver los slots de este entrenador.");
        }
    
        // Llamar al servicio
        List<TimeSlotDTO> slots = trainerScheduleService.getWeeklySlotsForTrainer(trainerId);
        System.out.println("Obtenidos " + slots.size() + " slots. Respondiendo 200 OK.");
        System.out.println("=== FIN Controller weekly-slots ===\n");
        return ResponseEntity.ok(slots);
    }
    
    
    @PostMapping("/book")
    public ResponseEntity<?> bookSlot(
        @RequestParam Long trainerId,
        @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime slotStart,
        Authentication authentication){

        // Por ejemplo, mostramos en logs:
        System.out.println("==========");
        System.out.println("trainerId: " + trainerId);
        System.out.println("slotStart (ZonedDateTime): " + slotStart);
        System.out.println("==========");

        String userEmail = authentication.getName();
  
 

      

        // Ejemplo: Delegar al servicio la lógica de reservar
        boolean success = trainerScheduleService.bookSlot(userEmail, trainerId, slotStart);
        // ^ Ajusta la firma de tu método service según tu lógica

        if (success) {
            return ResponseEntity.ok("Reserva exitosa");
        } else {
            return ResponseEntity.status(409).body("El slot no está disponible.");
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

    @GetMapping("/{trainerId}/existing-booking")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> getExistingBooking(
        @PathVariable Long trainerId,
        @RequestParam String slotStart,
        Authentication authentication) {
        
        String email = authentication.getName();
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
    
        LocalDateTime startDateTime = LocalDateTime.parse(slotStart, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    
        LocalDate slotDate = startDateTime.toLocalDate();
        Optional<Booking> existingBooking = bookingRepository
            .findByUserIdAndTrainerIdAndStartDateTimeBetween(
                 user.getId(), trainerId,
                 slotDate.atStartOfDay(), slotDate.atTime(23, 59)
            ).stream().findFirst();
        
        if (existingBooking.isPresent()) {
            return ResponseEntity.ok(existingBooking.get());
        }
    
        return ResponseEntity.ok().body(null);
    }
    

    @DeleteMapping("/cancel-booking/{bookingId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> cancelBooking(@PathVariable Long bookingId, Authentication authentication) {
        String email = authentication.getName();
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
    
        trainerScheduleService.cancelBooking(bookingId, user.getId());
    
        return ResponseEntity.ok("Reserva cancelada y bloque liberado con éxito");
    }
    
}
