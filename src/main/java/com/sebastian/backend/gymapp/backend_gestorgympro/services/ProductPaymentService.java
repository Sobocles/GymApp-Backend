package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.OrderDetail;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.User;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.OrderDetailRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago.MercadoPagoService;

@Service
public class ProductPaymentService {

    @Autowired
    private UserService userService;
    @Autowired
    private PaymentService paymentService;
    @Autowired
    private PaymentCreationService paymentCreationService;

    @Autowired
    private ProductService productService;

        @Autowired
    private OrderDetailRepository orderDetailRepository;
   public Preference createProductPayment(String userEmail, List<Map<String, Object>> items) throws MPException {
        User user = userService.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        BigDecimal totalPrice = BigDecimal.ZERO;

        // 1. Crear Payment (como hasta ahora)
        Payment payment = new Payment();
        payment.setUser(user);
        payment.setTransactionAmount(BigDecimal.ZERO); // Temporal, lo calcularemos
        payment.setStatus("pending");
        payment.setPlanIncluded(false);
        payment.setTrainerIncluded(false);

        // 2. Guardar payment para obtener su ID (o podrías hacerlo al final con cascade)
        paymentService.savePayment(payment);

        // 3. Crear la lista de OrderDetail
        for (Map<String, Object> item : items) {
            Long productId = Long.valueOf(item.get("productId").toString());
            Product product = productService.getProductById(productId);

            BigDecimal unitPrice = new BigDecimal(item.get("unitPrice").toString());
            int quantity = Integer.parseInt(item.get("quantity").toString());

            BigDecimal lineTotal = unitPrice.multiply(BigDecimal.valueOf(quantity));

            // Instanciar OrderDetail
            OrderDetail od = new OrderDetail();
            od.setPayment(payment);
            od.setProduct(product);
            od.setQuantity(quantity);
            od.setUnitPrice(unitPrice);
            od.setLineTotal(lineTotal);

            // Guardar
            orderDetailRepository.save(od);

            // Actualizar totalPrice
            totalPrice = totalPrice.add(lineTotal);
        }

        // 4. Actualizar el total en Payment
        payment.setTransactionAmount(totalPrice);
        paymentService.savePayment(payment);

        // 5. Crear preferencia en MercadoPago
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
