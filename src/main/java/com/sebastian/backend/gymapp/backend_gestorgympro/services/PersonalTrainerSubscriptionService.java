// PersonalTrainerSubscriptionService.java
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.util.List;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;

public interface PersonalTrainerSubscriptionService {

    void createSubscriptionForTrainerOnly(Payment payment, PersonalTrainer trainer);

    List<PersonalTrainerSubscription> getSubscriptionsByUserId(Long userId);
    
    boolean hasActiveTrainerSubscription(Long userId, Long trainerId);
}
