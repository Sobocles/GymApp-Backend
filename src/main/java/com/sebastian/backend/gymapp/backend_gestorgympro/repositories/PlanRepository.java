package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;

public interface PlanRepository extends JpaRepository<Plan, Long> {
    // Métodos personalizados si es necesario
}

