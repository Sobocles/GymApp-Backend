package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
        List<Payment> findByUserId(Long userId);
}
