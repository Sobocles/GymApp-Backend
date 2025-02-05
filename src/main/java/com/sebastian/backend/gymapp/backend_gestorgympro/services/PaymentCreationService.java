package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago.MercadoPagoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class PaymentCreationService {

    @Autowired
    private MercadoPagoService mercadoPagoService;

    @Autowired
    private PaymentService paymentService;

    // Inyectamos las URLs desde application.properties
    @Value("${mercadopago.successUrl}")
    private String successUrl;

    @Value("${mercadopago.failureUrl}")
    private String failureUrl;

    @Value("${mercadopago.pendingUrl}")
    private String pendingUrl;

    public Preference createPayment(Payment payment, String description) throws MPException {
        System.out.println("=== Creando pago ===");
        System.out.println("Usuario: " + (payment.getUser() != null ? payment.getUser().getEmail() : "NULO"));
        System.out.println("Monto: " + payment.getTransactionAmount());
        System.out.println("Estado: " + payment.getStatus());

        // Validar que el usuario no sea nulo
        if (payment.getUser() == null) {
            throw new IllegalArgumentException("El usuario no puede ser nulo en el pago.");
        }

        // Guardar el pago inicial (pendiente)
        paymentService.savePayment(payment);

        // Verificar si el ID es nulo después de guardar
        if (payment.getId() == null) {
            throw new IllegalStateException("El ID del pago es nulo después de guardarlo.");
        }

        // Generar referencia externa
        String externalReference = payment.getId().toString();
        payment.setExternalReference(externalReference);
        paymentService.savePayment(payment);

        // Crear preferencia en Mercado Pago
        return mercadoPagoService.createPreference(
                description,
                1,
                payment.getTransactionAmount(),
                successUrl,
                failureUrl,
                pendingUrl,
                payment.getUser().getEmail(),
                externalReference
        );
    }
}

