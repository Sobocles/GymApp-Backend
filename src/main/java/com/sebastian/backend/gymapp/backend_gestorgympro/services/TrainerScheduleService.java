package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.CalendarEventDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.TimeSlotDTO;

import java.time.LocalDateTime;
import java.util.List;

public interface TrainerScheduleService {
    List<TimeSlotDTO> getWeeklySlotsForTrainer(Long trainerId);
    boolean bookSlot(Long userId, Long trainerId, LocalDateTime slotStart);
    List<CalendarEventDTO> getTrainerCalendar(Long trainerId);
    List<CalendarEventDTO> getClientSessions(Long clientId);
}

