package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;

import java.time.LocalDateTime;
import java.util.List;

    public interface GroupClassRepository extends JpaRepository<GroupClass, Long> {
        List<GroupClass> findByStartTimeAfter(LocalDateTime now);

    @Query("SELECT gc FROM GroupClass gc WHERE gc.assignedTrainer.id = :trainerId")
    List<GroupClass> findByAssignedTrainerId(@Param("trainerId") Long trainerId);


    }
