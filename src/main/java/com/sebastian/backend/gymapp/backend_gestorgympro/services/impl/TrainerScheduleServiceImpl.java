package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerAvailability;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.BookingRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerAvailabilityRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.UserRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerScheduleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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

   @Override
@Transactional(readOnly = true)
public List<TimeSlotDTO> getWeeklySlotsForTrainer(Long trainerId) {
    LocalDate today = LocalDate.now();
    LocalDate monday = today.with(DayOfWeek.MONDAY);
    LocalDate sunday = monday.plusDays(6);

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

        // Verificar si ya está reservado
        boolean booked = bookingRepository.existsByTrainerIdAndSlotStart(trainerId, slotStart);
        if (booked) {
            return false; // ya reservado
        }

        Booking booking = new Booking();
        booking.setUser(user);
        booking.setTrainer(trainer);
        booking.setStartDateTime(slotStart);
        booking.setEndDateTime(slotStart.plusHours(1)); // Asumiendo que cada slot dura 1 hora

        bookingRepository.save(booking);
        return true;
    }
}
