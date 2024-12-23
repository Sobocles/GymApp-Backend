package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    public BigDecimal getRevenueByPlanType(String planType) {
        System.out.println("Parámetro planType recibido: " + planType);
        BigDecimal result = paymentRepository.getRevenueByPlanType(planType);
        return result != null ? result : BigDecimal.ZERO;
    }
    
    

    
    /**
         * Obtiene la suma total de todos los pagos registrados.
         *
         * @return La suma total de los pagos como BigDecimal.
         */
        public BigDecimal getTotalRevenue() {
            return paymentRepository.getTotalRevenue();
        }

     
    
    public BigDecimal getTotalRevenueByServiceType(Payment.serviceType serviceType) {
        System.out.println("Parámetro serviceType recibido: " + serviceType);
        return paymentRepository.getTotalRevenueByServiceType(serviceType);
    }
    

    public boolean existsByServiceType(Payment.serviceType serviceType) {
        return paymentRepository.existsByServiceType(serviceType);
    }

    public BigDecimal getRevenueByIncludedFlags(boolean planIncluded, boolean trainerIncluded) {
        return paymentRepository.getRevenueByIncludedFlags(planIncluded, trainerIncluded);
    }

     public Map<String, Object> getAdminDashboardRevenue() {
        Map<String, Object> dashboardRevenue = new HashMap<>();

        // 1. Ingresos por servicios
        Map<String, BigDecimal> serviceRevenue = new HashMap<>();
        serviceRevenue.put("personalTrainer", paymentRepository.getRevenueByIncludedFlags(false, true));
        serviceRevenue.put("planAndTrainer", paymentRepository.getRevenueByIncludedFlags(true, true));
        serviceRevenue.put("plan", paymentRepository.getRevenueByIncludedFlags(true, false));

        dashboardRevenue.put("serviceRevenue", serviceRevenue);

        // 2. Ingresos dinámicos por planes
        Map<String, BigDecimal> planRevenue = new HashMap<>();
        List<Object[]> revenueByPlan = paymentRepository.getRevenueGroupedByPlanName();
        for (Object[] row : revenueByPlan) {
            String planName = (String) row[0];
            BigDecimal total = (BigDecimal) row[1];
            planRevenue.put(planName, total);
        }

        dashboardRevenue.put("planRevenue", planRevenue);

        return dashboardRevenue;
    }
    
    
}

