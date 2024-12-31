package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClassBooking;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;



public interface GroupClassBookingRepository extends JpaRepository<GroupClassBooking, Long> {

    @Query("SELECT COUNT(b) FROM GroupClassBooking b WHERE b.groupClass.id = :classId")
    long countByGroupClassId(@Param("classId") Long classId);

    boolean existsByUserIdAndGroupClassId(Long userId, Long groupClassId);

  


}

