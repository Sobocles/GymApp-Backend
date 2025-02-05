package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Booking;

import java.time.LocalDate;
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

    List<Booking> findByTrainerId(Long trainerId);

       @Query("SELECT COUNT(b) > 0 FROM Booking b WHERE b.user.id = :userId AND b.trainer.id = :trainerId AND DATE(b.startDateTime) = :slotDate")
    boolean existsByUserIdAndTrainerIdAndSlotDate(@Param("userId") Long userId,
                                                  @Param("trainerId") Long trainerId,
                                                  @Param("slotDate") LocalDate slotDate);

    // Contar reservas durante la semana
    @Query("SELECT COUNT(b) FROM Booking b WHERE b.user.id = :userId AND b.trainer.id = :trainerId AND DATE(b.startDateTime) BETWEEN :startOfWeek AND :endOfWeek")
    long countByUserIdAndTrainerIdAndSlotDateBetween(@Param("userId") Long userId,
                                                     @Param("trainerId") Long trainerId,
                                                     @Param("startOfWeek") LocalDate startOfWeek,
                                                     @Param("endOfWeek") LocalDate endOfWeek);

                                                     List<Booking> findByUserIdAndTrainerIdAndStartDateTimeBetween(Long userId, Long trainerId, LocalDateTime start, LocalDateTime end);

                                                     List<Booking> findByUserId(Long userId);

                                                     @Query("SELECT b FROM Booking b WHERE b.user.id = :userId " +
                                                     "AND b.startDateTime <= :endDate AND b.trainer.id = :trainerId")
                                              List<Booking> findActiveBookingsWithinSubscription(@Param("userId") Long userId,
                                                                                                 @Param("trainerId") Long trainerId,
                                                                                                 @Param("endDate") LocalDateTime endDate);
                                              
           @Modifying
    @Query("UPDATE Booking b SET b.trainer.id = :newTrainerId WHERE b.trainer.id = :oldTrainerId")
    void updateTrainerForBookings(@Param("oldTrainerId") Long oldTrainerId, 
                                 @Param("newTrainerId") Long newTrainerId);
}
