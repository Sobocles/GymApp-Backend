package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago.MercadoPagoService;

@Service
public class ProductPaymentService {

    @Autowired
    private UserService userService;
    @Autowired
    private PaymentService paymentService;
    @Autowired
    private PaymentCreationService paymentCreationService;

    public Preference createProductPayment(String userEmail, List<Map<String, Object>> items) throws MPException {
        // 1. Buscar usuario
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        // 2. Calcular precio total
        BigDecimal totalPrice = BigDecimal.ZERO;
        for (Map<String, Object> item : items) {
            BigDecimal unitPrice = new BigDecimal(item.get("unitPrice").toString());
            int quantity = Integer.parseInt(item.get("quantity").toString());
            totalPrice = totalPrice.add(unitPrice.multiply(BigDecimal.valueOf(quantity)));
        }

        // 3. Crear Payment en DB
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setTransactionAmount(totalPrice);
        payment.setStatus("pending");
        payment.setPlanIncluded(false);
        payment.setTrainerIncluded(false);

        paymentService.savePayment(payment);

        // 4. Crear preferencia
        return paymentCreationService.createPayment(payment, "Compra de Productos");
    }

    public Preference createSingleProductPayment(String userEmail, Long productId, Integer quantity, 
                                                 ProductService productService,
                                                 String successUrl, String failureUrl, String pendingUrl,
                                                 MercadoPagoService mercadoPagoService) throws MPException {
        // 1. User
        User user = userService.findByEmail(userEmail)
            .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        // 2. Producto
        Product product = productService.getProductById(productId); // lanza excepción si no existe
        BigDecimal unitPrice = product.getPrice();
        BigDecimal totalPrice = unitPrice.multiply(BigDecimal.valueOf(quantity));

        // 3. Payment
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setStatus("pending");
        payment.setTransactionAmount(totalPrice);
        payment.setPaymentMethod("Mercado Pago");
        paymentService.savePayment(payment);

        // 4. Generar externalReference
        String externalReference = payment.getId().toString();
        payment.setExternalReference(externalReference);
        paymentService.savePayment(payment);

        // 5. Crear preferencia
        return mercadoPagoService.createPreference(
            product.getName(),
            quantity,
            unitPrice,
            successUrl,
            failureUrl,
            pendingUrl,
            user.getEmail(),
            externalReference
        );
    }
}
