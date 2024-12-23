package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;

import java.time.LocalDateTime;
import java.util.List;

public interface BookingRepository extends JpaRepository<Booking, Long> {
    List<Booking> findByTrainerIdAndStartDateTimeBetween(Long trainerId, LocalDateTime start, LocalDateTime end);

    @Query("SELECT COUNT(b) > 0 FROM Booking b WHERE b.trainer.id = :trainerId AND b.startDateTime = :slotStart")
    boolean existsByTrainerIdAndSlotStart(@Param("trainerId") Long trainerId, @Param("slotStart") LocalDateTime slotStart);
    
      /**
     * Verifica si existe alguna reserva de entrenamiento personal para el entrenador con ID dado,
     * que se solape con el rango [startTime, endTime].
     * Esta consulta asume que cada booking tiene startDateTime y endDateTime.
     */
    @Query("SELECT COUNT(b) > 0 FROM Booking b " +
           "WHERE b.trainer.id = :trainerId " +
           "AND ((b.startDateTime < :endTime AND b.endDateTime > :startTime))")
    boolean hasOverlappingBookings(Long trainerId, LocalDateTime startTime, LocalDateTime endTime);
}
