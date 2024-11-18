package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PaymentRepository;

@Service
public class PaymentService {

    @Autowired
    private PaymentRepository paymentRepository;

    public Payment savePayment(Payment payment) {
        return paymentRepository.save(payment);
    }

    public List<Payment> getPaymentsByUserId(Long userId) {
        return paymentRepository.findByUserId(userId);
    }


}

