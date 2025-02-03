package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;

import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentPersonalTrainerDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentPlanDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentProductDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.OrderDetailRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentNotificationService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentReportService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanTrainerPaymentService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProductPaymentService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;


import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;



@RestController
@RequestMapping("/payment")
public class PaymentController {

 

    @Autowired
    private PaymentReportService paymentReportService;

    @Autowired
    private PlanTrainerPaymentService planTrainerPaymentService;

    @Autowired
    private PaymentNotificationService paymentNotificationService;

        @Autowired
    private ProductPaymentService productPaymentService;

    @Autowired
    private PaymentService paymentService;

    

  

    @Value("${mercadopago.successUrl}")
    private String successUrl;

    @Value("${mercadopago.failureUrl}")
    private String failureUrl;

    @Value("${mercadopago.pendingUrl}")
    private String pendingUrl;
    
    @PostMapping("/create_plan_preference")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Preference createPlanPaymentPreference(
            @RequestParam(required = false) Long planId,
            @RequestParam(required = false) Long trainerId,
            @RequestParam(required = false, defaultValue = "false") boolean onlyTrainer
    ) throws MPException {
        // 1. Obtener el email del usuario autenticado
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();

        // 2. Delegar toda la lógica al servicio
        return planTrainerPaymentService.createPlanTrainerPayment(userEmail, planId, trainerId, onlyTrainer);
    }
    

    @PostMapping("/create_product_preference")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Preference createProductPaymentPreference(
            @RequestBody List<Map<String, Object>> items,
            Authentication authentication) throws MPException {

        String userEmail = authentication.getName();
        return productPaymentService.createProductPayment(userEmail, items);
    }
    
    
    @PostMapping("/notifications")
    public ResponseEntity<String> receiveNotification(@RequestParam Map<String, String> params) {
        try {
            paymentNotificationService.processNotification(params);
            return ResponseEntity.ok("Received");
        } catch (MPException | MPApiException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error al procesar la notificación");
        }
    }
    
    
    @GetMapping("/my-payments")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<PaymentDTO>> getMyPayments(Authentication authentication) {
        try {
            List<PaymentDTO> payments = paymentReportService.getMyPayments(authentication.getName());
            return ResponseEntity.ok(payments);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/total-revenue")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, BigDecimal>> getTotalRevenue() {
        try {
            Map<String, BigDecimal> revenue = paymentReportService.getTotalRevenueBreakdown();
            return ResponseEntity.ok(revenue);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", BigDecimal.ZERO));
        }
    }

        @GetMapping("/admin-dashboard-revenue")
        @PreAuthorize("hasRole('ADMIN')")
        public ResponseEntity<Map<String, Object>> getAdminDashboardRevenue() {
            try {
                Map<String, Object> revenue = paymentReportService.getAdminDashboardRevenue();
                return ResponseEntity.ok(revenue);
            } catch (Exception e) {
                return ResponseEntity.status(500).body(Map.of("error", "Error interno del servidor"));
            }
        }

        @GetMapping("/personal_trainer")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PaymentPersonalTrainerDTO>> getApprovedPersonalTrainerPayments() {
        List<PaymentPersonalTrainerDTO> payments = paymentService.getApprovedPersonalTrainerPayments();
        return ResponseEntity.ok(payments);
    }


    @GetMapping("/approved_plans/page/{page}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<PaymentPlanDTO>> getApprovedPlanPaymentsPage(
        @PathVariable int page,
        @RequestParam(defaultValue = "6") int size,
        @RequestParam(defaultValue = "") String search) { // Nuevo parámetro de búsqueda
        
        Pageable pageable = PageRequest.of(page, size);
        Page<PaymentPlanDTO> paymentsPage = paymentService.getApprovedPlanPaymentsPage(pageable, search);
        return ResponseEntity.ok(paymentsPage);
    }

    @GetMapping("/approved_products/page/{page}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Page<PaymentProductDTO>> getApprovedProductPaymentsPage(
        @PathVariable int page,
        @RequestParam(defaultValue = "6") int size,
        @RequestParam(defaultValue = "") String search
    ) {
        Pageable pageable = PageRequest.of(page, size);
        Page<PaymentProductDTO> paymentsPage = paymentService.getApprovedProductPaymentsPage(pageable, search);
        return ResponseEntity.ok(paymentsPage);
    }
    

        @GetMapping("/details/mp/{mpPaymentId}")
        public ResponseEntity<PaymentDTO> getPaymentDetailsByMPId(@PathVariable String mpPaymentId) {
            // Buscar el pago basado en el ID de Mercado Pago
            Payment payment = paymentService.getPaymentByMercadoPagoId(mpPaymentId)
                    .orElseThrow(() -> new RuntimeException("No se encontró Payment con MP ID: " + mpPaymentId));
        
            // Construcción del DTO
            PaymentDTO dto = paymentService.buildPaymentDto(payment);
            return ResponseEntity.ok(dto);
        }
        
        
        
    
    

}
