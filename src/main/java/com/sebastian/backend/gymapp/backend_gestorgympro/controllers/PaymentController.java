package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.mercadopago.client.payment.PaymentClient;
import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;

import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.UserService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PersonalTrainerSubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago.MercadoPagoService;

import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;

import java.math.BigDecimal;
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

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    // NUEVO: Inyectamos el servicio de PersonalTrainerSubscription
    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Value("${mercadopago.successUrl}")
    private String successUrl;

    @Value("${mercadopago.failureUrl}")
    private String failureUrl;

    @Value("${mercadopago.pendingUrl}")
    private String pendingUrl;

    @PostMapping("/create_preference")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Preference createPaymentPreference(
            @RequestParam(required = false) Long planId,
            @RequestParam(required = false) Long trainerId,
            @RequestParam(required = false, defaultValue = "false") boolean onlyTrainer
    ) throws MPException {

        System.out.println("=== createPaymentPreference llamado ===");
        System.out.println("Parámetros recibidos: planId=" + planId + ", trainerId=" + trainerId + ", onlyTrainer=" + onlyTrainer);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            System.out.println("Usuario no autenticado!");
            throw new IllegalArgumentException("Usuario no autenticado");
        }

        String currentEmail = authentication.getName();
        System.out.println("Email del usuario autenticado: " + currentEmail);
        Optional<User> userOpt = userService.findByEmail(currentEmail);
        if (userOpt.isEmpty()) {
            System.out.println("Usuario no encontrado en base de datos con email: " + currentEmail);
            throw new IllegalArgumentException("Usuario no encontrado");
        }

        User user = userOpt.get();
        String payerEmail = user.getEmail();
        System.out.println("Usuario encontrado: " + user.getUsername() + " (Email: " + payerEmail + ")");

        BigDecimal totalPrice = BigDecimal.ZERO;
        Plan plan = null;
        PersonalTrainer trainer = null;

        // Verificar logicamente si es onlyTrainer y planId no debe venir
        if (onlyTrainer && planId != null) {
            System.out.println("Error: Se solicitó onlyTrainer pero se pasó un planId");
            throw new IllegalArgumentException("No se puede comprar sólo entrenador si se pasó un planId");
        }

        if (planId != null) {
            plan = planService.getPlanById(planId);
            if (plan == null) {
                System.out.println("Plan no encontrado con planId: " + planId);
                throw new IllegalArgumentException("Plan no encontrado");
            }
            System.out.println("Plan encontrado: " + plan.getName() + " precio: " + plan.getPrice());
            totalPrice = totalPrice.add(plan.getPrice());
        }

        if (trainerId != null) {
            System.out.println("Buscando entrenador con trainerId: " + trainerId);
            trainer = personalTrainerRepository.findById(trainerId)
                    .orElseThrow(() -> {
                        System.out.println("No se encontró entrenador con ID: " + trainerId);
                        return new IllegalArgumentException("Entrenador no encontrado");
                    });

            System.out.println("Entrenador encontrado: " + trainer.getUser().getUsername() +
                    " disponibilidad: " + trainer.getAvailability() +
                    " monthlyFee: " + trainer.getMonthlyFee());

            if (!trainer.getAvailability()) {
                System.out.println("El entrenador no está disponible");
                throw new IllegalArgumentException("El entrenador no está disponible");
            }
            if (trainer.getMonthlyFee() == null) {
                System.out.println("El entrenador no tiene monthlyFee definido");
                throw new IllegalArgumentException("El entrenador no tiene definido un monthlyFee");
            }
            totalPrice = totalPrice.add(trainer.getMonthlyFee());
        }

        if (totalPrice.compareTo(BigDecimal.ZERO) == 0) {
            System.out.println("No se especificó ni plan ni entrenador. totalPrice=0");
            throw new IllegalArgumentException("No se especificó plan ni entrenador, no hay nada que comprar");
        }

        Payment payment = new Payment();
        payment.setUser(user);
        payment.setPlan(plan);
        payment.setStatus("pending");
        payment.setTransactionAmount(totalPrice);
        payment.setPaymentMethod("Mercado Pago");
        payment.setTrainerId(trainer != null ? trainer.getId() : null);
        payment.setTrainerIncluded(trainer != null);
        payment.setPlanIncluded(plan != null);
        paymentService.savePayment(payment);

        String externalReference = payment.getId().toString();
        payment.setExternalReference(externalReference);
        paymentService.savePayment(payment);

        System.out.println("Creando preferencia en MercadoPago con totalPrice: " + totalPrice + ", plan: " + (plan != null ? plan.getName() : "Ninguno") + ", entrenadorId: " + (trainer != null ? trainer.getId() : null));

        Preference preference = mercadoPagoService.createPreference(
                plan != null ? plan.getName() : "Entrenador",
                1,
                totalPrice,
                successUrl,
                failureUrl,
                pendingUrl,
                payerEmail,
                externalReference
        );

        System.out.println("Preferencia creada en MercadoPago: " + (preference != null ? preference.getId() : "null"));
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

                    if ("approved".equals(payment.getStatus().toString())) {
                        // Crear la suscripción al plan si existe plan incluido
                        if (dbPayment.isPlanIncluded()) {
                            subscriptionService.createSubscriptionForPayment(dbPayment);
                        }

                        // Crear la suscripción al personal trainer si existe trainer incluido
                        if (dbPayment.isTrainerIncluded()) {
                            // Llamamos a createSubscriptionForTrainerOnly desde personalTrainerSubscriptionService
                            personalTrainerSubscriptionService.createSubscriptionForTrainerOnly(dbPayment);
                        }
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
