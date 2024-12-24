package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.mercadopago.client.payment.PaymentClient;
import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;

import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Plan;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.TrainerClient;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PersonalTrainerRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.TrainerClientRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.PaymentCreationService;
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

    @Autowired
    private PaymentCreationService paymentCreationService;



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
    
        System.out.println("=== createPlanPaymentPreference llamado ===");
        System.out.println("Parámetros recibidos: planId=" + planId + ", trainerId=" + trainerId + ", onlyTrainer=" + onlyTrainer);
    
        // 1. Obtener usuario autenticado
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = userService.findByEmail(authentication.getName())
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
        System.out.println("Usuario autenticado: " + user.getEmail());
    
        BigDecimal totalPrice = BigDecimal.ZERO;
        Plan plan = null;
        PersonalTrainer trainer = null;
    
        // 2. Validación de opciones (Plan + Trainer, Solo Plan, Solo Trainer)
        if (onlyTrainer && planId != null) {
            System.out.println("Error: No se puede comprar solo entrenador si se selecciona un plan.");
            throw new IllegalArgumentException("No se puede comprar solo entrenador si se selecciona un plan.");
        }
    
        // 3. Procesar compra de plan (si se especifica)
        if (planId != null) {
            System.out.println("Intentando obtener plan con ID: " + planId);
            plan = planService.getPlanById(planId);
            if (plan == null) {
                System.out.println("Plan no encontrado con ID: " + planId);
                throw new IllegalArgumentException("Plan no encontrado con ID: " + planId);
            }
            totalPrice = totalPrice.add(plan.getPrice());
            System.out.println("Plan seleccionado: " + plan.getName() + " | Precio: " + plan.getPrice());
        } else {
            System.out.println("No se seleccionó ningún plan.");
        }
    
        // 4. Procesar compra de entrenador (si se especifica)
        if (trainerId != null) {
            System.out.println("Intentando obtener entrenador con ID: " + trainerId);
            trainer = personalTrainerRepository.findById(trainerId)
                    .orElseThrow(() -> {
                        System.out.println("Entrenador no encontrado con ID: " + trainerId);
                        return new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId);
                    });
    
            if (!trainer.getAvailability()) {
                System.out.println("Error: El entrenador con ID " + trainerId + " no está disponible.");
                throw new IllegalArgumentException("El entrenador no está disponible.");
            }
            if (trainer.getMonthlyFee() == null) {
                System.out.println("Error: El entrenador con ID " + trainerId + " no tiene tarifa definida.");
                throw new IllegalArgumentException("El entrenador no tiene una tarifa definida.");
            }
    
            totalPrice = totalPrice.add(trainer.getMonthlyFee());
            System.out.println("Entrenador seleccionado: " + trainer.getUser().getUsername() + " | Precio: " + trainer.getMonthlyFee());
        } else {
            System.out.println("No se seleccionó ningún entrenador.");
        }
    
        // 5. Validación final (No permitir transacción vacía)
        System.out.println("Total price antes de validación final: " + totalPrice);
        if (totalPrice.compareTo(BigDecimal.ZERO) == 0) {
            System.out.println("Error: Debe seleccionar al menos un plan o un entrenador.");
            throw new IllegalArgumentException("Debe seleccionar al menos un plan o un entrenador.");
        }
    
        // 6. Crear el pago con el servicio compartido
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setPlan(plan);
        payment.setTrainerId(trainer != null ? trainer.getId() : null);
        payment.setStatus("pending");
        payment.setTransactionAmount(totalPrice);
        payment.setTrainerIncluded(trainer != null);
        payment.setPlanIncluded(plan != null);
    
        System.out.println("Creando pago con monto total: " + totalPrice);
        return paymentCreationService.createPayment(payment, "Compra de Plan/Entrenador");
    }
    

    @PostMapping("/create_product_preference")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Preference createProductPaymentPreference(
            @RequestBody List<Map<String, Object>> items) throws MPException {
    
        // 1. Obtener usuario autenticado
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = userService.findByEmail(authentication.getName())
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));
    
        // 2. Calcular precio total de los productos
        BigDecimal totalPrice = BigDecimal.ZERO;
        for (Map<String, Object> item : items) {
            BigDecimal unitPrice = new BigDecimal(item.get("unitPrice").toString());
            int quantity = Integer.parseInt(item.get("quantity").toString());
            totalPrice = totalPrice.add(unitPrice.multiply(BigDecimal.valueOf(quantity)));
        }
    
        // 3. Crear el objeto de Payment (igual que en la compra de planes)
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setTransactionAmount(totalPrice);
        payment.setStatus("pending");
        payment.setPlanIncluded(false);  // No es un plan
        payment.setTrainerIncluded(false);  // No hay entrenador

        System.out.println("Preparando pago: Usuario=" + user.getEmail() + ", Monto=" + totalPrice);

    
        // 4. Llamar al método createPayment con el objeto Payment
        return paymentCreationService.createPayment(payment, "Compra de Productos");
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

    @GetMapping("/total-revenue")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, BigDecimal>> getTotalRevenue() {
        try {
            BigDecimal totalRevenue = paymentService.getTotalRevenue();
            return ResponseEntity.ok(Map.of("totalRevenue", totalRevenue));
        } catch (Exception e) {
            System.err.println("Error al obtener la suma total de ingresos: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", BigDecimal.ZERO));
        }
    }
/* 
    @GetMapping("/revenue-by-service-type/{serviceType}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, BigDecimal>> getRevenueByServiceType(@PathVariable String serviceType) {
        try {
            // Convertir el parámetro de ruta a ServiceType enum
            Payment.serviceType type = Payment.serviceType.valueOf(serviceType.toUpperCase());

            BigDecimal totalRevenue = paymentService.getTotalRevenueByServiceType(type);
            return ResponseEntity.ok(Map.of(
                "serviceType", new BigDecimal(type.ordinal()), // Para incluir el tipo de servicio en la respuesta
                "totalRevenue", totalRevenue
            ));
        } catch (IllegalArgumentException e) {
            // Maneja el caso en que el serviceType proporcionado no es válido
            return ResponseEntity.badRequest().body(Map.of("error", BigDecimal.ZERO));
        } catch (Exception e) {
            System.err.println("Error al obtener la suma total de ingresos por tipo de servicio: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", BigDecimal.ZERO));
        }
    }
*/
    @GetMapping("/admin-dashboard-revenue")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAdminDashboardRevenue() {
        try {
            System.out.println("AQUI ENTRO");
            BigDecimal planRevenue = paymentService.getRevenueByIncludedFlags(true, false); // Solo plan
            System.out.println(planRevenue);
            BigDecimal trainerRevenue = paymentService.getRevenueByIncludedFlags(false, true); 
            System.out.println(trainerRevenue);
            BigDecimal combinedRevenue = paymentService.getRevenueByIncludedFlags(true, true); // Ambos
            System.out.println(combinedRevenue);
           

            Map<String, Object> revenue = paymentService.getAdminDashboardRevenue();
            return ResponseEntity.ok(revenue);


        } catch (Exception e) {
            System.err.println("Error al obtener los datos del dashboard: " + e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Error interno del servidor"));
        }
    }

    @PostMapping("/create_preference_product")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public Preference createPreferenceForSingleProduct(
        @RequestParam Long productId,
        @RequestParam Integer quantity
    ) throws MPException {
        // 1. Verificar usuario autenticado
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("Usuario no autenticado");
        }
        String userEmail = authentication.getName();
        User user = userService.findByEmail(userEmail)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        // 2. Buscar el producto en la base de datos
        Product product = productService.getProductById(productId); // lanza excepción si no existe

        // 3. Calcular precio total
        BigDecimal unitPrice = product.getPrice(); // asume BigDecimal
        BigDecimal totalPrice = unitPrice.multiply(BigDecimal.valueOf(quantity));

        // 4. Crear registro Payment en la base de datos (estado pending)
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setStatus("pending");
        payment.setTransactionAmount(totalPrice);
        payment.setPaymentMethod("Mercado Pago");
        
        // (Opcional) asignar un nuevo campo "serviceType=PRODUCT" o similar, si lo deseas
        payment.setServiceType(Payment.serviceType.PLAN); // O crea algo: PRODUCT
        paymentService.savePayment(payment);

        // 5. Generar externalReference y actualizar Payment
        String externalReference = payment.getId().toString();
        payment.setExternalReference(externalReference);
        paymentService.savePayment(payment);

        // 6. Crear la preferencia en Mercado Pago usando tu servicio mercadoPagoService
        // Aqui agregas 1 item con el "title" = product name, "quantity"= quantity, "unitPrice"= totalPrice/ quantity 
        // O creas un item con "unitPrice=productPrice" y quantity=...
        Preference preference = mercadoPagoService.createPreference(
            product.getName(),
            quantity,
            unitPrice, // precio unitario
            successUrl,
            failureUrl,
            pendingUrl,
            user.getEmail(),
            externalReference
        );

        return preference; // Retorna la preferencia, luego en el frontend rediriges a initPoint
    }

    
    

}
