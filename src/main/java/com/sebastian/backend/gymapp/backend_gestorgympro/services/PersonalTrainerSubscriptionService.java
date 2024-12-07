// PersonalTrainerSubscriptionService.java
package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.util.List;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainerSubscription;

public interface PersonalTrainerSubscriptionService {
    void createSubscriptionForTrainerOnly(Payment payment);
    List<PersonalTrainerSubscription> getSubscriptionsByUserId(Long userId);
}
