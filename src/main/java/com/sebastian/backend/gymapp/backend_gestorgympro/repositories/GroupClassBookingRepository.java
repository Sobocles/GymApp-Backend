package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClassBooking;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface GroupClassBookingRepository extends JpaRepository<GroupClassBooking, Long> {
    long countByGroupClassId(Long groupClassId);
    boolean existsByUserIdAndGroupClassId(Long userId, Long groupClassId);
}

