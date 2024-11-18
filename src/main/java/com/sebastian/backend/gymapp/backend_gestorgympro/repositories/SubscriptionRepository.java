package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import java.util.List;

public interface SubscriptionRepository extends JpaRepository<Subscription, Long> {
    List<Subscription> findByUserId(Long userId);
    List<Subscription> findByPlanId(Long planId);
    // Otros métodos personalizados
}
