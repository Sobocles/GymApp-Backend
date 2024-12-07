package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;

public interface PersonalTrainerSubscriptionRepository extends JpaRepository<PersonalTrainerSubscription, Long> {
    List<PersonalTrainerSubscription> findByUserId(Long userId);
    Optional<PersonalTrainerSubscription> findByPaymentId(Long paymentId);
    
}

