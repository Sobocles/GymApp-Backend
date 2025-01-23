package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mercadopago.client.payment.PaymentClient;
import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.OrderDetail;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.PersonalTrainer;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.OrderDetailRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.ProductRepository;

@Service
public class PaymentNotificationService {

    @Autowired
    private PaymentService paymentService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private SubscriptionService subscriptionService;

    @Autowired
    private PersonalTrainerSubscriptionService personalTrainerSubscriptionService;

    @Autowired
    private TrainerService trainerService;

    @Autowired
    private OrderDetailRepository orderDetailRepository;

    @Autowired
    private ProductRepository productRepository;

    public void processNotification(Map<String, String> params) throws MPException, MPApiException {
        System.out.println("Notificación recibida: " + params);

        String topic = params.get("topic");
        String type = params.get("type");
        String id = params.get("id");
        String dataId = params.get("data.id");

        // Validar que sea pago
        if ("payment".equals(topic) || "payment".equals(type)) {
            if (id == null) {
                id = dataId;
            }
            System.out.println("ID del pago a procesar: " + id);

            PaymentClient paymentClient = new PaymentClient();
            com.mercadopago.resources.payment.Payment mpPayment = paymentClient.get(Long.parseLong(id));
            System.out.println("Detalle del pago desde MP: " + mpPayment);

            String externalReference = mpPayment.getExternalReference();
            Optional<Payment> optPayment = paymentService.getPaymentByExternalReference(externalReference);

            if (optPayment.isPresent()) {
                Payment dbPayment = optPayment.get();
                System.out.println("Payment en DB: " + dbPayment);

                // Actualizar estado
                dbPayment.setStatus(mpPayment.getStatus().toString());
                if (mpPayment.getDateApproved() != null) {
                    dbPayment.setPaymentDate(mpPayment.getDateApproved().toLocalDateTime());
                }
                dbPayment.setMercadoPagoId(mpPayment.getId().toString());
                dbPayment.setUpdateDate(LocalDateTime.now());
                dbPayment.setPaymentMethod(mpPayment.getPaymentMethodId()); 
                
                System.out.println(dbPayment);

                paymentService.savePayment(dbPayment);

                // Si está aprobado => manejar suscripciones y correo
                if ("approved".equals(mpPayment.getStatus().toString())) {
                    System.out.println("El pago está aprobado. Procesando suscripciones...");
                    String destinatario = dbPayment.getUser().getEmail();
                    String asunto = "Confirmación de Pago";
                    String cuerpo = "Hola " + dbPayment.getUser().getUsername() + ", tu pago se ha realizado con éxito.";
                    emailService.sendEmail(destinatario, asunto, cuerpo);

                    if (dbPayment.isPlanIncluded()) {
                        handlePlanSubscription(dbPayment);
                    }
                    if (dbPayment.isTrainerIncluded()) {
                        handleTrainerSubscription(dbPayment);
                    }

                    List<OrderDetail> details = orderDetailRepository.findByPaymentId(dbPayment.getId());
                    for (OrderDetail od : details) {
                        Product p = od.getProduct();

                        System.out.println("Producto antes de actualizar:");
                        System.out.println("Nombre: " + p.getName());
                        System.out.println("Stock actual: " + p.getStock());
                        System.out.println("Cantidad comprada: " + od.getQuantity());
                    
                        // Incrementar salesCount por la cantidad comprada
                        int nuevoSalesCount = p.getSalesCount() + od.getQuantity();
                        p.setSalesCount(nuevoSalesCount);

                        System.out.println("salesCount"+p.getSalesCount());
                    
                        // Restar stock por la cantidad comprada
                        p.setStock(p.getStock() - od.getQuantity());

                        System.out.println("cantidad de stock"+p.getStock());
                    
                        // Guardar el producto actualizado
                        productRepository.save(p);
                    
                        System.out.println("Ventas y stock actualizados para el producto: " + p.getName() +
                                           ". Ventas totales: " + nuevoSalesCount +
                                           ", Stock restante: " + p.getStock());
                    }
                    
                }

            } else {
                System.out.println("Payment no encontrado en la DB para reference: " + externalReference);
            }
        } else {
            System.out.println("Notificación no es de tipo 'payment'. Ignorando.");
        }
    }

    private void handlePlanSubscription(Payment dbPayment) {
        // Crear la suscripción del plan
        Subscription subscription = subscriptionService.createSubscriptionForPayment(dbPayment);
        System.out.println("Suscripción creada: " + subscription);

        // Manejar entrenadores incluidos en el plan
        List<PersonalTrainer> includedTrainers = subscription.getPlan().getIncludedTrainers();
        if (includedTrainers != null) {
            for (PersonalTrainer trainer : includedTrainers) {
                personalTrainerSubscriptionService.createSubscriptionForTrainerOnly(dbPayment, trainer);
                Long trainerId = trainer.getId();
                Long clientUserId = dbPayment.getUser().getId();
                trainerService.addClientToTrainer(trainerId, clientUserId);
                System.out.println("Cliente asignado al entrenador " + trainerId);
            }
        }
    }

    private void handleTrainerSubscription(Payment dbPayment) {
        Long trainerId = dbPayment.getTrainerId();
        PersonalTrainer trainer = trainerService.findPersonalTrainerById(trainerId)
            .orElseThrow(() -> new IllegalArgumentException("Entrenador no encontrado con ID: " + trainerId));
        System.out.println("Entrenador encontrado para suscripción: " + trainer);

        personalTrainerSubscriptionService.createSubscriptionForTrainerOnly(dbPayment, trainer);
        Long clientUserId = dbPayment.getUser().getId();
        trainerService.addClientToTrainer(trainerId, clientUserId);
        System.out.println("Cliente asignado al entrenador (Trainer ID: " + trainerId +
                           ", Client ID: " + clientUserId + ")");
    }
}
