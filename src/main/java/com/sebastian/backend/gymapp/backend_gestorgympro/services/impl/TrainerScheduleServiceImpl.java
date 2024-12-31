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
    LocalDate today = LocalDate.now();
    LocalDate monday = today.with(DayOfWeek.MONDAY);
    LocalDate sunday = monday.plusWeeks(2);  // Extiende a dos semanas


    System.out.println("Calculando slots para el entrenador: " + trainerId);
    System.out.println("Rango de fechas: " + monday + " a " + sunday);

    List<TrainerAvailability> availabilities = trainerAvailabilityRepository.findByTrainerIdAndDayBetween(trainerId, monday, sunday);
    System.out.println("Disponibilidades encontradas en la base de datos: " + availabilities);

    List<TimeSlotDTO> slots = new ArrayList<>();

    for (TrainerAvailability availability : availabilities) {
        LocalDate date = availability.getDay();
        LocalTime startTime = availability.getStartTime();
        LocalTime endTime = availability.getEndTime();
        System.out.println("Procesando disponibilidad: " + date + " " + startTime + " - " + endTime);

        LocalTime slotStart = startTime;
        while (slotStart.plusHours(1).isBefore(endTime) || slotStart.plusHours(1).equals(endTime)) {
            LocalTime slotEnd = slotStart.plusHours(1);
            LocalDateTime start = LocalDateTime.of(date, slotStart);
            LocalDateTime end = LocalDateTime.of(date, slotEnd);

            boolean booked = bookingRepository.existsByTrainerIdAndSlotStart(trainerId, start);
            System.out.println("Slot generado: " + start + " - " + end + ", reservado: " + booked);

            TimeSlotDTO dto = new TimeSlotDTO();
            dto.setTrainerId(trainerId);
            dto.setStartDateTime(start);
            dto.setEndDateTime(end);
            dto.setAvailable(!booked);
            slots.add(dto);

            slotStart = slotEnd;
        }
    }

    System.out.println("Total de slots generados: " + slots.size());
    return slots;
}

        @Override
        @Transactional
        public boolean bookSlot(Long userId, Long trainerId, LocalDateTime slotStart) {
            // Verificar que el entrenador existe
            PersonalTrainer trainer = personalTrainerRepository.findById(trainerId)
                    .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado"));

            // Verificar que el usuario existe
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

            LocalDate slotDate = slotStart.toLocalDate();

            // Validar si ya tiene una reserva el mismo día
            boolean alreadyBookedToday = bookingRepository.existsByUserIdAndTrainerIdAndSlotDate(userId, trainerId, slotDate);
            if (alreadyBookedToday) {
                throw new IllegalStateException("Ya tienes una reserva con este entrenador para el mismo día.");
            }

            // Validar si tiene más de 5 reservas en la misma semana
            LocalDate startOfWeek = slotDate.with(DayOfWeek.MONDAY);
            LocalDate endOfWeek = startOfWeek.plusDays(6);
            long weeklyBookings = bookingRepository.countByUserIdAndTrainerIdAndSlotDateBetween(userId, trainerId, startOfWeek, endOfWeek);
            if (weeklyBookings >= 5) {
                throw new IllegalStateException("Has alcanzado el límite de 5 reservas semanales con este entrenador.");
            }

            // Verificar si ya está reservado ese slot
            boolean booked = bookingRepository.existsByTrainerIdAndSlotStart(trainerId, slotStart);
            if (booked) {
                throw new IllegalStateException("Este horario ya ha sido reservado por otro usuario.");
            }

            // Proceder con la reserva
            Booking booking = new Booking();
            booking.setUser(user);
            booking.setTrainer(trainer);
            booking.setStartDateTime(slotStart);
            booking.setEndDateTime(slotStart.plusHours(1)); 

            bookingRepository.save(booking);
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

    

    
}
