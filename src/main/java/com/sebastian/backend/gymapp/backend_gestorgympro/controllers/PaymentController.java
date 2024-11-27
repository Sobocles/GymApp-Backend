package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.mercadopago.client.payment.PaymentClient;
import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;

import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago.MercadoPagoService;

import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;


import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;


@RestController
@RequestMapping("/payment")
public class PaymentController {

    @Autowired
    private MercadoPagoService mercadoPagoService;

    @Autowired
    private PaymentService paymentService;

    @Autowired
    private PlanService planService;

    @Autowired
    private UserService userService;

    @Autowired
    private SubscriptionService subscriptionService;

    @Value("${mercadopago.successUrl}")
    private String successUrl;

    @Value("${mercadopago.failureUrl}")
    private String failureUrl;

    @Value("${mercadopago.pendingUrl}")
    private String pendingUrl;

    @PostMapping("/create_preference")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Preference createPaymentPreference(
            @RequestParam Long planId) throws MPException {
                System.out.println("Entró al método createPaymentPreference con planId: " + planId);
        Plan plan = planService.getPlanById(planId);
        
        System.out.println("AQUI EL PLAN"+plan);
        if (plan == null) {
            throw new IllegalArgumentException("Plan no encontrado");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("PaymentController - Objeto de autenticación: " + authentication);
        
        if (authentication == null || !authentication.isAuthenticated()) {
            System.out.println("PaymentController - Usuario no autenticado");
            throw new IllegalArgumentException("Usuario no autenticado");
        }

        // Obtener el email del usuario autenticado
        String currentEmail = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("PaymentController - Email del usuario autenticado: " + currentEmail);
        Optional<User> userOpt = userService.findByEmail(currentEmail);
        if (userOpt.isEmpty()) {
            throw new IllegalArgumentException("Usuario no encontrado");
        }
        User user = userOpt.get();

        String payerEmail = user.getEmail();
        System.out.println("Email del usuario de prueba comprador: " + payerEmail);

    // Crear y guardar el pago en la base de datos
    Payment payment = new Payment();
    payment.setUser(user);
    payment.setPlan(plan);
    payment.setStatus("pending");
    payment.setTransactionAmount(plan.getPrice());
    payment.setPaymentMethod("Mercado Pago");
    paymentService.savePayment(payment);

    // Obtener el ID del pago y usarlo como external_reference
    String externalReference = payment.getId().toString();
    payment.setExternalReference(externalReference);
    paymentService.savePayment(payment);

    // Crear la preferencia de pago con external_reference
    Preference preference = mercadoPagoService.createPreference(
            plan.getName(),
            1,
            plan.getPrice(),
            successUrl,
            failureUrl,
            pendingUrl,
            payerEmail,
            externalReference // Pasa el external_reference
    );

    // No es necesario guardar el preference.getId() en el pago
    // ya que usaremos external_reference para la asociación

        return preference;
    }
    @PostMapping("/notifications")
    public ResponseEntity<String> receiveNotification(@RequestParam Map<String, String> params) {
        System.out.println("Notificación recibida: " + params);
    
        String topic = params.get("topic");
        String id = params.get("id");
        String type = params.get("type");
        String dataId = params.get("data.id");
    
        try {
            if ("payment".equals(topic) || "payment".equals(type)) {
                if (id == null) {
                    id = dataId;
                }
    
                // Obtener el detalle del pago desde Mercado Pago
                PaymentClient paymentClient = new PaymentClient();
                com.mercadopago.resources.payment.Payment payment = paymentClient.get(Long.parseLong(id));
    
                // Obtener el externalReference
                String externalReference = payment.getExternalReference();
    
                // Actualizar el estado y mercado_pago_id del pago en tu base de datos
                Optional<Payment> optionalPayment = paymentService.getPaymentByExternalReference(externalReference);
                if (optionalPayment.isPresent()) {
                    Payment dbPayment = optionalPayment.get();
                    dbPayment.setStatus(payment.getStatus().toString());
                    if (payment.getDateApproved() != null) {
                        dbPayment.setPaymentDate(payment.getDateApproved().toLocalDateTime());
                    }
                    dbPayment.setMercadoPagoId(payment.getId().toString()); // Actualizar mercado_pago_id
                    dbPayment.setUpdateDate(LocalDateTime.now()); // Actualizar fecha de actualización
                    paymentService.savePayment(dbPayment);
    
                    // Si el pago fue aprobado, crear la suscripción
                    if ("approved".equals(payment.getStatus().toString())) {
                        subscriptionService.createSubscriptionForPayment(dbPayment);
                    }
                } else {
                    System.out.println("PaymentController - Payment no encontrado con externalReference: " + externalReference);
                }
            }
            // ... manejar otros tipos de notificaciones si es necesario ...
    
        } catch (MPException | MPApiException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al procesar la notificación");
        }
    
        return ResponseEntity.ok("Received");
    }

       @GetMapping("/my-payments")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<PaymentDTO>> getMyPayments(Authentication authentication) {
        try {
            String email = authentication.getName();
            System.out.println("Email del usuario autenticado: " + email);

            Optional<User> userOpt = userService.findByEmail(email);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            User user = userOpt.get();
            List<PaymentDTO> payments = paymentService.getPaymentsByUserId(user.getId());
            return ResponseEntity.ok(payments);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    


}
