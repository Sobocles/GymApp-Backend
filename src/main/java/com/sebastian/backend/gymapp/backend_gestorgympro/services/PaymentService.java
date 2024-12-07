package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PaymentRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.SubscriptionRepository;

@Service
public class PaymentService {

    @Autowired
    private PaymentRepository paymentRepository;

    @Autowired
    private SubscriptionRepository subscriptionRepository;

    public Payment savePayment(Payment payment) {
        return paymentRepository.save(payment);
    }

    public List<PaymentDTO> getPaymentsByUserId(Long userId) {
        List<Payment> payments = paymentRepository.findByUserId(userId);
        return payments.stream().map(payment -> {
            PaymentDTO dto = new PaymentDTO();
            dto.setId(payment.getId());
    
            // Si el plan es nulo, ponle un valor por defecto, por ejemplo "Solo Entrenador"
            String planName = (payment.getPlan() != null) ? payment.getPlan().getName() : "Sin Plan (Solo Entrenador)";
            
            dto.setPlanName(planName);
            dto.setPaymentDate(payment.getPaymentDate());
            dto.setPaymentMethod(payment.getPaymentMethod());
            dto.setTransactionAmount(payment.getTransactionAmount());
    
            // Obtener la suscripción asociada
            Optional<Subscription> subscriptionOpt = subscriptionRepository.findByPaymentId(payment.getId());
            if (subscriptionOpt.isPresent()) {
                Subscription subscription = subscriptionOpt.get();
                dto.setSubscriptionStartDate(subscription.getStartDate());
                dto.setSubscriptionEndDate(subscription.getEndDate());
            }
    
            return dto;
        }).collect(Collectors.toList());
    }
    

    public Optional<Payment> getPaymentByMercadoPagoId(String mercadoPagoId) {
        return paymentRepository.findByMercadoPagoId(mercadoPagoId);
    }

    public Optional<Payment> getPaymentByExternalReference(String externalReference) {
        return paymentRepository.findByExternalReference(externalReference);
    }

    
    


}

