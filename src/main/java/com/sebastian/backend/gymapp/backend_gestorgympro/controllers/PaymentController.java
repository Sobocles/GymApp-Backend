package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.mercadopago.MercadoPago;
import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.Preference;
import com.mercadopago.resources.Payment as MercadoPagoPayment;
import java.util.List;

@RestController
@RequestMapping("/payment")
public class PaymentController {

    @Autowired
    private PaymentService paymentService;

    @Autowired
    private PlanService planService;

    @Autowired
    private UserService userService;

    @Value("${mercadopago.accessToken}")
    private String mercadoPagoAccessToken;

    @PostMapping("/create_preference")
    public ResponseEntity<?> createPreference(@RequestParam Long planId) throws MPException {
        // Lógica para crear la preferencia de pago como se explicó anteriormente
    }

    @PostMapping("/webhook")
    public ResponseEntity<?> handleWebhook(@RequestBody Map<String, Object> payload) {
        // Lógica para manejar las notificaciones de Mercado Pago
    }

    // Otros métodos según necesidades...
}

