package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.GroupClass.GroupClass;

import java.time.LocalDateTime;
import java.util.List;

public interface GroupClassRepository extends JpaRepository<GroupClass, Long> {
    List<GroupClass> findByStartTimeAfter(LocalDateTime now);
}
