package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;

public interface PlanRepository extends JpaRepository<Plan, Long> {
        // Encuentra todos los planes activos
        List<Plan> findByActiveTrue();

        // Si también quieres uno para filtrar inactivos:
        List<Plan> findByActiveFalse();
}

