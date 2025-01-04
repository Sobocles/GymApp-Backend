package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PaymentRepository;

@Service
public class PaymentReportService {

    @Autowired
    private PaymentService paymentService;

    @Autowired
    private UserService userService;

    @Autowired
    private PaymentRepository paymentRepository;

    public List<PaymentDTO> getMyPayments(String userEmail) {
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
        return paymentService.getPaymentsByUserId(user.getId());
    }

    public Map<String, BigDecimal> getTotalRevenueBreakdown() {
        // Total general (todos los ingresos aprobados)
        BigDecimal totalRevenue = paymentRepository.getTotalApprovedRevenue();
        
        // Total de ingresos por planes
        BigDecimal planRevenue = paymentRepository.getTotalApprovedPlanRevenue();
        
        // Total de ingresos por productos
        BigDecimal productRevenue = paymentRepository.getTotalApprovedProductRevenue();

        // Devolver los valores en un Map
        return Map.of(
            "totalRevenue", totalRevenue,
            "planRevenue", planRevenue,
            "productRevenue", productRevenue
        );
    }

    public Map<String, Object> getAdminDashboardRevenue() {
        return paymentService.getAdminDashboardRevenue();
    }
}

