package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;

public interface PaymentRepository extends JpaRepository<Payment, Long> {
        List<Payment> findByUserId(Long userId);
        Optional<Payment> findByMercadoPagoId(String mercadoPagoId);
        Optional<Payment> findByExternalReference(String externalReference);

}
