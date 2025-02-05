package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;

public interface PlanRepository extends JpaRepository<Plan, Long> {
        // Encuentra todos los planes activos
        List<Plan> findByActiveTrue();

        // Si también quieres uno para filtrar inactivos:
        List<Plan> findByActiveFalse();

        @Query("SELECT p FROM Plan p JOIN p.includedTrainers t WHERE t.id = :trainerId")
    List<Plan> findAllByIncludedTrainersId(@Param("trainerId") Long trainerId);
}

