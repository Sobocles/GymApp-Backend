package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerAvailability;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.GroupClassRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class TrainerScheduleServiceImpl implements TrainerScheduleService {

    @Autowired
    private TrainerAvailabilityRepository trainerAvailabilityRepository;

    @Autowired
    private BookingRepository bookingRepository;

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    @Autowired
    private UserRepository userRepository;


    @Autowired
    private GroupClassRepository groupClassRepository;

    @Autowired
    private  PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Override
    @Transactional(readOnly = true)
    public List<TimeSlotDTO> getWeeklySlotsForTrainer(Long trainerId) {
        System.out.println("=== getWeeklySlotsForTrainer ===");
        System.out.println("trainerId: " + trainerId);
    
        LocalDate today = LocalDate.now();
        LocalDate monday = today.with(DayOfWeek.MONDAY);
        LocalDate sunday = monday.plusWeeks(3);  // extiende a 2 semanas
        System.out.println("Rango de búsqueda: " + monday + " -> " + sunday);
    
        // Buscar en trainerAvailabilityRepository
        List<TrainerAvailability> availabilities = 
            trainerAvailabilityRepository.findByTrainerIdAndDayBetween(trainerId, monday, sunday);
    
        System.out.println("Se obtuvieron " + availabilities.size() + " TrainerAvailability. Detalle:");
        for (TrainerAvailability av : availabilities) {
            System.out.println("  - ID=" + av.getId() + " " 
                               + av.getDay() + " " 
                               + av.getStartTime() + "-" + av.getEndTime());
        }
    
        List<TimeSlotDTO> slots = new ArrayList<>();
    
        for (TrainerAvailability availability : availabilities) {
            LocalDate date = availability.getDay();
            LocalTime startTime = availability.getStartTime();
            LocalTime endTime = availability.getEndTime();
    
            System.out.println("Generando horas para " + date + " [" + startTime + " - " + endTime + "]");
            LocalTime slotStart = startTime;
            while (!slotStart.plusHours(1).isAfter(endTime)) {
                LocalTime slotEnd = slotStart.plusHours(1);
                LocalDateTime start = LocalDateTime.of(date, slotStart);
                LocalDateTime end = LocalDateTime.of(date, slotEnd);
    
                // Verificar si ese slot ya está en 'bookings' => setear available=false
                boolean isBooked = bookingRepository.existsByTrainerIdAndSlotStart(trainerId, start);
                // Ejem: or las validaciones que tengas
                TimeSlotDTO dto = new TimeSlotDTO();
                dto.setTrainerId(trainerId);
                dto.setStartDateTime(start);
                dto.setEndDateTime(end);
                dto.setAvailable(!isBooked);
    
                slots.add(dto);
                slotStart = slotEnd;
            }
        }
        System.out.println("TOTAL de slots generados: " + slots.size());
        for (TimeSlotDTO s : slots) {
            System.out.println("  => " + s.getStartDateTime() 
                               + " - " + s.getEndDateTime() 
                               + " available=" + s.isAvailable());
        }
    
        System.out.println("=== FIN getWeeklySlotsForTrainer ===\n");
        return slots;
    }
    

        
    @Transactional
    @Override
    public boolean bookSlot(String userEmail, Long trainerId, LocalDateTime slotStart) {
        // 1) Verificar duplicado, lógica extra, etc. (omitido aquí)
        //    Supongamos ya comprobaste que el slot está libre, etc.
        
        // 2) Obtener el usuario y el entrenador reales
        User user = userRepository.findByEmailAndActiveTrue(userEmail)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
    
        PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
            .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado"));
    
        // 3) Crear y guardar la Booking real
        Booking booking = new Booking();
        booking.setUser(user);
        booking.setTrainer(trainer);
        booking.setStartDateTime(slotStart);
        booking.setEndDateTime(slotStart.plusHours(1));
    
        bookingRepository.save(booking);
    
        // 4) Partir la availability
        LocalDate day   = slotStart.toLocalDate();
        LocalTime start = slotStart.toLocalTime();
        LocalTime end   = start.plusHours(1);
    
        // Asegúrate de tener este método en tu repo (query custom o filtrar en memoria)
        List<TrainerAvailability> sameDay = trainerAvailabilityRepository
           .findByTrainerIdAndDay(trainerId, day);
    
        for (TrainerAvailability av : sameDay) {
            LocalTime avStart = av.getStartTime();
            LocalTime avEnd   = av.getEndTime();
    
            // Si se solapa con [start, end], partimos.
            // La condición "avStart < end && avEnd > start" detecta solapamiento
            if (avStart.isBefore(end) && avEnd.isAfter(start)) {
    
                // 1) Eliminar la fila original:
                trainerAvailabilityRepository.delete(av);
    
                // 2) Crear la parte "izquierda" [avStart..start], si es válida:
                if (avStart.isBefore(start)) {
                    TrainerAvailability left = new TrainerAvailability();
                    left.setTrainer(trainer);
                    left.setDay(day);
                    left.setStartTime(avStart);
                    left.setEndTime(start);
    
                    trainerAvailabilityRepository.save(left);
                }
    
                // 3) Crear la parte "derecha" [end..avEnd], si es válida:
                if (end.isBefore(avEnd)) {
                    TrainerAvailability right = new TrainerAvailability();
                    right.setTrainer(trainer);
                    right.setDay(day);
                    right.setStartTime(end);
                    right.setEndTime(avEnd);
    
                    trainerAvailabilityRepository.save(right);
                }
            }
        }
    
        return true;
    }
    
    



      @Transactional(readOnly = true)
    public List<CalendarEventDTO> getTrainerCalendar(Long trainerId) {
        // 1. Obtener bookings (entrenos personales) para ese trainer
        List<Booking> personalBookings = bookingRepository.findByTrainerId(trainerId);

        // 2. Convertirlos a CalendarEventDTO
        List<CalendarEventDTO> personalEvents = personalBookings.stream()
            .map(b -> {
                CalendarEventDTO dto = new CalendarEventDTO();
                dto.setId(b.getId());
                // El "title" puede ser algo como "Sesión con <nombre del cliente>"
                dto.setTitle("Entreno con " + b.getUser().getUsername());
                dto.setStart(b.getStartDateTime());
                dto.setEnd(b.getEndDateTime());
                dto.setEventType("PERSONAL");
                return dto;
            })
            .collect(Collectors.toList());

        // 3. Obtener las clases grupales donde assignedTrainer = trainerId
        List<GroupClass> groupClasses = groupClassRepository.findByAssignedTrainerId(trainerId);

        // 4. Convertirlas a CalendarEventDTO
        List<CalendarEventDTO> groupEvents = groupClasses.stream()
            .map(gc -> {
                CalendarEventDTO dto = new CalendarEventDTO();
                dto.setId(gc.getId());
                dto.setTitle("Clase: " + gc.getClassName());
                dto.setStart(gc.getStartTime());
                dto.setEnd(gc.getEndTime());
                dto.setEventType("GROUP");
                return dto;
            })
            .collect(Collectors.toList());

        // 5. Unir ambas listas
        List<CalendarEventDTO> allEvents = new ArrayList<>();
        allEvents.addAll(personalEvents);
        allEvents.addAll(groupEvents);

        return allEvents;
    }

  
   @Override
@Transactional(readOnly = true)
public List<CalendarEventDTO> getClientSessions(Long clientId) {
    List<Booking> bookings = bookingRepository.findByUserId(clientId);
    List<CalendarEventDTO> futureSessions = new ArrayList<>();

    for (Booking booking : bookings) {
        LocalDateTime start = booking.getStartDateTime();
        LocalDateTime end = booking.getEndDateTime();

        // Obtener la fecha de fin de suscripción
        Optional<PersonalTrainerSubscription> activeSub = personalTrainerSubscriptionService
                .findActiveSubscriptionForUser(clientId);

        if (activeSub.isPresent()) {
            LocalDate endDate = activeSub.get().getEndDate();

            // Repetir semanalmente hasta la fecha de fin de suscripción
            while (start.toLocalDate().isBefore(endDate)) {
                CalendarEventDTO dto = new CalendarEventDTO();
                dto.setId(booking.getId());
                dto.setTitle("Sesión con " + booking.getTrainer().getUser().getUsername());
                dto.setStart(start);
                dto.setEnd(end);
                dto.setEventType("PERSONAL");
                futureSessions.add(dto);

                // Incrementar 1 semana para la próxima sesión
                start = start.plusWeeks(1);
                end = end.plusWeeks(1);
            }
        }
    }

    return futureSessions;
}

@Transactional
@Override
public boolean cancelBooking(Long bookingId, Long userId) {
    Booking booking = bookingRepository.findById(bookingId)
        .orElseThrow(() -> {
            System.out.println("Reserva no encontrada con ID: " + bookingId);
            return new IllegalArgumentException("Reserva no encontrada");
        });

    if (!booking.getUser().getId().equals(userId)) {
        System.out.println("Usuario no autorizado para cancelar esta reserva. Usuario ID: " + userId);
        throw new IllegalStateException("No tienes permiso para cancelar esta reserva");
    }

    System.out.println("Cancelando reserva con ID: " + bookingId);

    // Elimina la reserva
    bookingRepository.delete(booking);
    System.out.println("Reserva eliminada correctamente");

    // Actualiza la tabla de disponibilidad para re-liberar la franja
    LocalDate day     = booking.getStartDateTime().toLocalDate();
    LocalTime startT  = booking.getStartDateTime().toLocalTime();
    LocalTime endT    = booking.getEndDateTime().toLocalTime();
    Long trainerId    = booking.getTrainer().getId();

    System.out.println("Liberando franja para el entrenador ID: " + trainerId + " en fecha: " + day + 
                       " desde " + startT + " hasta " + endT);

    // Buscar rangos que se solapen o toquen la franja cancelada
    List<TrainerAvailability> sameDayRanges = trainerAvailabilityRepository
        .findByTrainerIdAndDay(trainerId, day);
    
    System.out.println("Disponibilidades encontradas ese día: " + sameDayRanges.size());

    List<TrainerAvailability> nuevos = new ArrayList<>();

    // Iterar sobre cada franja de disponibilidad
    for (TrainerAvailability av : sameDayRanges) {
        LocalTime avStart = av.getStartTime();
        LocalTime avEnd   = av.getEndTime();

        System.out.println("Evaluando disponibilidad: " + avStart + " - " + avEnd);

        if (avEnd.isBefore(startT) || avStart.isAfter(endT)) {
            System.out.println("No hay solapamiento con: " + avStart + " - " + avEnd);
            nuevos.add(av);
            continue;
        }

        // Solapamiento detectado, eliminamos y reconstruimos
        System.out.println("Solapamiento detectado, eliminando disponibilidad: " + avStart + " - " + avEnd);
        trainerAvailabilityRepository.delete(av);

        LocalTime minStart = (avStart.isBefore(startT)) ? avStart : startT;
        LocalTime maxEnd   = (avEnd.isAfter(endT)) ? avEnd : endT;

        TrainerAvailability tmp = new TrainerAvailability();
        tmp.setTrainer(booking.getTrainer());
        tmp.setDay(day);
        tmp.setStartTime(minStart);
        tmp.setEndTime(maxEnd);

        System.out.println("Nueva disponibilidad temporal: " + minStart + " - " + maxEnd);
        nuevos.add(tmp);
    }

    // Unir los rangos que se solapan
    nuevos.sort(Comparator.comparing(TrainerAvailability::getStartTime));
    List<TrainerAvailability> merged = new ArrayList<>();

    for (TrainerAvailability current : nuevos) {
        if (merged.isEmpty()) {
            merged.add(current);
        } else {
            TrainerAvailability last = merged.get(merged.size() - 1);
            if (!last.getEndTime().isBefore(current.getStartTime())) {
                LocalTime unionEnd = last.getEndTime().isAfter(current.getEndTime())
                                     ? last.getEndTime() : current.getEndTime();
                last.setEndTime(unionEnd);
                System.out.println("Unión de disponibilidad: " + last.getStartTime() + " - " + unionEnd);
            } else {
                merged.add(current);
            }
        }
    }

    System.out.println("Guardando disponibilidades finales...");
    for (TrainerAvailability m : merged) {
        System.out.println("Guardando: " + m.getStartTime() + " - " + m.getEndTime());
        trainerAvailabilityRepository.save(m);
    }

    System.out.println("Proceso de cancelación completado exitosamente");
    return true;
}






    

    
}
