package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.mercadopago.client.payment.PaymentClient;
import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;

import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerClient;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerClientRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PlanService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.SubscriptionService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.TrainerService;
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
import java.util.UUID;

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
    private SubscriptionService subscriptionService; // Cambiado a la interfaz

    @Autowired
    private PersonalTrainerRepository personalTrainerRepository;

    // NUEVO: Inyectamos el servicio de PersonalTrainerSubscription
    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
private TrainerClientRepository trainerClientRepository;

    @Autowired
private TrainerService trainerService;



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
    
        // Obtener el usuario autenticado
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            System.out.println("Error: Usuario no autenticado!");
            throw new IllegalArgumentException("Usuario no autenticado");
        }
    
        String currentEmail = authentication.getName();
        System.out.println("Email del usuario autenticado obtenido del contexto de seguridad: " + currentEmail);
    
        // Buscar al usuario en la base de datos
        Optional<User> userOpt = userService.findByEmail(currentEmail);
        System.out.println("Resultado de la búsqueda del usuario autenticado (Optional<User>): " + userOpt);
    
        if (userOpt.isEmpty()) {
            System.out.println("Error: Usuario no encontrado en la base de datos con email: " + currentEmail);
            throw new IllegalArgumentException("Usuario no encontrado");
        }
    
        User user = userOpt.get();
        String payerEmail = user.getEmail();
        System.out.println("Usuario autenticado encontrado: " + user.getUsername() + " (Email: " + payerEmail + ")");
    
        BigDecimal totalPrice = BigDecimal.ZERO;
        Plan plan = null;
        PersonalTrainer trainer = null;
    
        // Validar la lógica de 'onlyTrainer'
        if (onlyTrainer && planId != null) {
            System.out.println("Error: Se solicitó onlyTrainer pero se pasó un planId");
            throw new IllegalArgumentException("No se puede comprar sólo entrenador si se pasó un planId");
        }
    
        // Procesar el plan, si existe
        if (planId != null) {
            plan = planService.getPlanById(planId);
            System.out.println("Resultado de la búsqueda del plan (Plan): " + plan);
    
            if (plan == null) {
                System.out.println("Error: Plan no encontrado con planId: " + planId);
                throw new IllegalArgumentException("Plan no encontrado");
            }
    
            System.out.println("Plan encontrado: " + plan.getName() + " (Precio: " + plan.getPrice() + ")");
            totalPrice = totalPrice.add(plan.getPrice());
            System.out.println("Precio total acumulado después de agregar el plan: " + totalPrice);
        }
    
        // Procesar el entrenador, si existe
        if (trainerId != null) {
            System.out.println("Buscando entrenador con trainerId: " + trainerId);
    
            trainer = personalTrainerRepository.findById(trainerId)
                    .orElseThrow(() -> {
                        System.out.println("Error: Entrenador no encontrado con ID: " + trainerId);
                        return new IllegalArgumentException("Entrenador no encontrado");
                    });
    
            System.out.println("Entrenador encontrado: " + trainer.getUser().getUsername() +
                    " (Disponibilidad: " + trainer.getAvailability() +
                    ", MonthlyFee: " + trainer.getMonthlyFee() + ")");
    
            if (!trainer.getAvailability()) {
                System.out.println("Error: El entrenador no está disponible");
                throw new IllegalArgumentException("El entrenador no está disponible");
            }
            if (trainer.getMonthlyFee() == null) {
                System.out.println("Error: El entrenador no tiene monthlyFee definido");
                throw new IllegalArgumentException("El entrenador no tiene definido un monthlyFee");
            }
    
            totalPrice = totalPrice.add(trainer.getMonthlyFee());
            System.out.println("Precio total acumulado después de agregar el entrenador: " + totalPrice);
        }
    
        // Validar que haya algo que comprar
        if (totalPrice.compareTo(BigDecimal.ZERO) == 0) {
            System.out.println("Error: No se especificó ni plan ni entrenador. totalPrice=0");
            throw new IllegalArgumentException("No se especificó plan ni entrenador, no hay nada que comprar");
        }
    
        // Crear el objeto Payment
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
        System.out.println("Objeto Payment creado y guardado en la base de datos: " + payment);
    
        // Establecer el externalReference y actualizar el Payment
        String externalReference = payment.getId().toString();
        System.out.println("Aqui esta el external reference"+externalReference);
        payment.setExternalReference(externalReference);
        paymentService.savePayment(payment);
        System.out.println("Payment actualizado con externalReference: " + externalReference);
    
        // Crear preferencia en Mercado Pago
        System.out.println("Creando preferencia en MercadoPago...");
        System.out.println("Detalles para la preferencia: totalPrice=" + totalPrice + 
                ", plan=" + (plan != null ? plan.getName() : "Ninguno") + 
                ", entrenadorId=" + (trainer != null ? trainer.getId() : "Ninguno"));
    
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
    
        System.out.println("Preferencia creada en MercadoPago con initPoint: " + preference.getInitPoint());
    
        return preference;
    }
    
    @PostMapping("/notifications")
    public ResponseEntity<String> receiveNotification(@RequestParam Map<String, String> params) {
        // Log inicial con todos los parámetros recibidos en la notificación
        System.out.println("Notificación recibida: " + params);
    
        // Extraer los valores relevantes de los parámetros
        String topic = params.get("topic");
        String id = params.get("id");
        String type = params.get("type");
        String dataId = params.get("data.id");
    
        // Log de los valores extraídos
        System.out.println("Valor de 'topic': " + topic);
        System.out.println("Valor de 'id': " + id);
        System.out.println("Valor de 'type': " + type);
        System.out.println("Valor de 'data.id': " + dataId);
    
        try {
            // Validar que el topic o type sean "payment"
            if ("payment".equals(topic) || "payment".equals(type)) {
                // Si no hay un ID directo, usar el dataId
                if (id == null) {
                    id = dataId;
                }
                System.out.println("ID del pago a procesar (id o dataId): " + id);
    
                // Obtener el detalle del pago desde Mercado Pago
                PaymentClient paymentClient = new PaymentClient();
                com.mercadopago.resources.payment.Payment payment = paymentClient.get(Long.parseLong(id));
                System.out.println("Detalle del pago obtenido desde Mercado Pago: " + payment);
    
                // Extraer y loguear detalles importantes del pago
                System.out.println("Estado del pago (status): " + payment.getStatus());
                System.out.println("Detalle del estado del pago (status_detail): " + payment.getStatusDetail());
                String externalReference = payment.getExternalReference();
                System.out.println("External Reference del pago: " + externalReference);
    
                // Buscar el pago en tu base de datos utilizando el externalReference
                Optional<Payment> optionalPayment = paymentService.getPaymentByExternalReference(externalReference);
                System.out.println("Resultado de la búsqueda del Payment por externalReference: " + optionalPayment);
    
                // Validar si el Payment existe en la base de datos
                if (optionalPayment.isPresent()) {
                    Payment dbPayment = optionalPayment.get();
                    System.out.println("Payment encontrado en la base de datos: " + dbPayment);
    
                    // Actualizar el estado del Payment en la base de datos
                    dbPayment.setStatus(payment.getStatus().toString());
                    if (payment.getDateApproved() != null) {
                        dbPayment.setPaymentDate(payment.getDateApproved().toLocalDateTime());
                    }
                    dbPayment.setMercadoPagoId(payment.getId().toString());
                    dbPayment.setUpdateDate(LocalDateTime.now());
                    paymentService.savePayment(dbPayment);
                    System.out.println("Payment actualizado en la base de datos: " + dbPayment);
    
                    // Manejar suscripciones si el estado del pago es "approved"
                    if ("approved".equals(payment.getStatus().toString())) {
                        System.out.println("El pago está aprobado. Procesando suscripciones...");
    
                        // Manejo de suscripciones al plan
                        if (dbPayment.isPlanIncluded()) {
                            Subscription subscription = subscriptionService.createSubscriptionForPayment(dbPayment);
                            System.out.println("Suscripción creada para el plan: " + subscription);
    
                            // Asociar entrenadores incluidos en el plan al usuario
                            List<PersonalTrainer> includedTrainers = subscription.getPlan().getIncludedTrainers();
                            if (includedTrainers != null) {
                                for (PersonalTrainer trainer : includedTrainers) {
                                    personalTrainerSubscriptionService.createSubscriptionForTrainerOnly(dbPayment, trainer);
                                    System.out.println("Suscripción creada para entrenador: " + trainer);
    
                                    Long trainerId = trainer.getId();
                                    Long clientUserId = dbPayment.getUser().getId();
                                    trainerService.addClientToTrainer(trainerId, clientUserId);
                                    System.out.println("Cliente asignado al entrenador (Trainer ID: " + trainerId +
                                            ", Client ID: " + clientUserId + ")");
                                }
                            }
                        }
    
                        // Manejo de suscripciones al entrenador
                        if (dbPayment.isTrainerIncluded()) {
                            Long trainerId = dbPayment.getTrainerId();
                            PersonalTrainer trainer = trainerService.findPersonalTrainerById(trainerId)
                                    .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));
                            System.out.println("Entrenador encontrado para suscripción: " + trainer);
    
                            personalTrainerSubscriptionService.createSubscriptionForTrainerOnly(dbPayment, trainer);
                            System.out.println("Suscripción creada para el entrenador: " + trainer);
    
                            Long clientUserId = dbPayment.getUser().getId();
                            trainerService.addClientToTrainer(trainerId, clientUserId);
                            System.out.println("Cliente asignado al entrenador (Trainer ID: " + trainerId +
                                    ", Client ID: " + clientUserId + ")");
                        }
                    }
    
                } else {
                    // Si no se encuentra el Payment en la base de datos
                    System.out.println("Payment no encontrado en la base de datos para el externalReference: " + externalReference);
                }
            } else {
                System.out.println("Notificación recibida no es de tipo 'payment'. Ignorando.");
            }
    
        } catch (MPException | MPApiException e) {
            System.out.println("Error al procesar la notificación: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al procesar la notificación");
        }
    
        // Retornar respuesta exitosa si no hay errores
        System.out.println("Notificación procesada correctamente.");
        return ResponseEntity.ok("Received");
    }
    
    

    @GetMapping("/my-payments")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<PaymentDTO>> getMyPayments(Authentication authentication) {
        try {
            // Extraer el email del usuario autenticado desde el objeto Authentication
            String email = authentication.getName();
            System.out.println("Email del usuario autenticado extraído del objeto Authentication: " + email);
    
            // Buscar al usuario autenticado en la base de datos utilizando el email
            Optional<User> userOpt = userService.findByEmail(email);
            System.out.println("Resultado de la búsqueda del usuario autenticado en la base de datos (Optional<User>): " + userOpt); //Se usa findByEmail(email) para obtener el Optional<User>. Esto permite manejar la posibilidad de que el usuario no exista.
    
            // Verificar si el usuario existe
            if (userOpt.isEmpty()) {
                System.out.println("Usuario no encontrado en la base de datos. Retornando respuesta UNAUTHORIZED.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
    
            // Obtener el usuario autenticado
            User user = userOpt.get(); //Esta verificación garantiza que cuando llegues a userOpt.get(), el valor esté presente, y por lo tanto no habrá excepciones inesperadas.
            System.out.println("Usuario autenticado obtenido del Optional<User>: " + user);
    
            // Consultar los pagos asociados al usuario por su ID
            List<PaymentDTO> payments = paymentService.getPaymentsByUserId(user.getId());
            System.out.println("Lista de pagos obtenida para el usuario autenticado (ID: " + user.getId() + "): " + payments);
    
            // Retornar la lista de pagos en la respuesta
            return ResponseEntity.ok(payments);
    
        } catch (Exception e) {
            // Imprimir la excepción en caso de error y retornar respuesta de error interno
            System.out.println("Ocurrió un error al procesar la solicitud de pagos: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }



    

}
