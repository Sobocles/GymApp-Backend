package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;

@Service
public class PaymentReportService {

    @Autowired
    private PaymentService paymentService;
    @Autowired
    private UserService userService;

    public List<PaymentDTO> getMyPayments(String userEmail) {
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
        return paymentService.getPaymentsByUserId(user.getId());
    }

    public BigDecimal getTotalRevenue() {
        return paymentService.getTotalRevenue();
    }

    public Map<String, Object> getAdminDashboardRevenue() {
        return paymentService.getAdminDashboardRevenue();
    }
}

