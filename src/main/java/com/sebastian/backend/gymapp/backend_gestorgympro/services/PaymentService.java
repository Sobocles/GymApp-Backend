package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentPersonalTrainerDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentPlanDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.PaymentProductDTO;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ProductDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.OrderDetail;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Payment;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Subscription;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.OrderDetailRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.PaymentRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.SubscriptionRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

@Service
public class PaymentService {

    @Autowired
    private PaymentRepository paymentRepository;

    @Autowired
    private SubscriptionRepository subscriptionRepository;

    @Autowired
    private EmailService emailService;

        @Autowired
    private OrderDetailRepository orderDetailRepository;

    public Payment savePayment(Payment payment) {
        Payment savedPayment = paymentRepository.save(payment);

        if ("approved".equals(payment.getStatus())) {
            sendPurchaseConfirmationEmail(payment);
        }

        return savedPayment;
    }

    public List<PaymentDTO> getPaymentsByUserId(Long userId) {
        List<Payment> payments = paymentRepository.findByUserIdAndStatus(userId, "approved");
        return payments.stream().map(payment -> {
            PaymentDTO dto = new PaymentDTO();
            dto.setId(payment.getId());
            dto.setPlanName(payment.getPlan() != null ? payment.getPlan().getName() : "Sin Plan");
            dto.setPaymentDate(payment.getPaymentDate());
            dto.setPaymentMethod(payment.getPaymentMethod());
            dto.setTransactionAmount(payment.getTransactionAmount());
            dto.setPaymentType(payment.getPaymentType());
            dto.setPaymentMethod(payment.getPaymentMethod());
    
            // Obtener productos relacionados desde los detalles del pedido
            List<OrderDetail> orderDetails = orderDetailRepository.findByPaymentId(payment.getId());
            List<ProductDto> productDtos = orderDetails.stream().map(orderDetail -> {
                Product product = orderDetail.getProduct();
                ProductDto productDto = new ProductDto();
                productDto.setName(product.getName());
                productDto.setPrice(product.getPrice().doubleValue());
                productDto.setDescription(product.getDescription());
                productDto.setBrand(product.getBrand());
                productDto.setFlavor(product.getFlavor());
                productDto.setImageUrl(product.getImageUrl());
                productDto.setPaymentMethod(payment.getPaymentMethod());
                return productDto;
            }).collect(Collectors.toList());
            dto.setProducts(productDtos);
    
            return dto;
        }).collect(Collectors.toList());
    }
    

    

    

    public Optional<Payment> getPaymentByMercadoPagoId(String mercadoPagoId) {
        return paymentRepository.findByMercadoPagoId(mercadoPagoId);
    }

    public Optional<Payment> getPaymentByExternalReference(String externalReference) {
        return paymentRepository.findByExternalReference(externalReference);
    }


    
    

    
  

     

    public BigDecimal getRevenueByIncludedFlags(boolean planIncluded, boolean trainerIncluded) {
        return paymentRepository.getRevenueByIncludedFlags(planIncluded, trainerIncluded);
    }

     public Map<String, Object> getAdminDashboardRevenue() {
        Map<String, Object> dashboardRevenue = new HashMap<>();

        // 1. Ingresos por servicios
        Map<String, BigDecimal> serviceRevenue = new HashMap<>();
        serviceRevenue.put("personalTrainer", paymentRepository.getRevenueByIncludedFlags(false, true));
        serviceRevenue.put("planAndTrainer", paymentRepository.getRevenueByIncludedFlags(true, true));
        serviceRevenue.put("plan", paymentRepository.getRevenueByIncludedFlags(true, false));

        dashboardRevenue.put("serviceRevenue", serviceRevenue);

        // 2. Ingresos dinámicos por planes
        Map<String, BigDecimal> planRevenue = new HashMap<>();
        List<Object[]> revenueByPlan = paymentRepository.getRevenueGroupedByPlanName();
        for (Object[] row : revenueByPlan) {
            String planName = (String) row[0];
            BigDecimal total = (BigDecimal) row[1];
            planRevenue.put(planName, total);
        }

        dashboardRevenue.put("planRevenue", planRevenue);

        return dashboardRevenue;
    }

 

    private void sendPurchaseConfirmationEmail(Payment payment) {
        String email = payment.getUser().getEmail();
        String subject = "Confirmación de Compra - GymPro";
        String body = "Hola " + payment.getUser().getUsername() + ",\n\n" +
                      "Gracias por tu compra. El total fue: $" + payment.getTransactionAmount() + "\n" +
                      "Detalles:\n" +
                      (payment.getPlan() != null ? "Plan: " + payment.getPlan().getName() + "\n" : "") +
                      (payment.getTrainerId() != null ? "Entrenador: " + payment.getTrainerId() + "\n" : "") +
                      "Estado: " + payment.getStatus() + "\n\n" +
                      "¡Gracias por confiar en nosotros!";
        
        emailService.sendEmail(email, subject, body);
    }
    
    public List<PaymentDTO> getAllApprovedPayments() {
        List<Payment> payments = paymentRepository.findByStatus("approved");
        return payments.stream().map(payment -> {
            PaymentDTO dto = new PaymentDTO();
            dto.setId(payment.getId());
            dto.setUserId(payment.getUser().getId());
            dto.setUsername(payment.getUser().getUsername());
            dto.setPlanName(payment.getPlan() != null ? payment.getPlan().getName() : "Sin Plan");
            dto.setPaymentDate(payment.getPaymentDate());
            dto.setPaymentMethod(payment.getPaymentMethod());
            dto.setTransactionAmount(payment.getTransactionAmount());
            dto.setPaymentType(payment.getPaymentType());

            if (payment.getSubscription() != null) {
                dto.setSubscriptionStartDate(payment.getSubscription().getStartDate());
                dto.setSubscriptionEndDate(payment.getSubscription().getEndDate());
            }

            // Obtener productos relacionados desde los detalles del pedido
            List<OrderDetail> orderDetails = orderDetailRepository.findByPaymentId(payment.getId());
            List<ProductDto> productDtos = orderDetails.stream().map(orderDetail -> {
                Product product = orderDetail.getProduct();
                ProductDto productDto = new ProductDto();
                productDto.setId(product.getId());
                productDto.setName(product.getName());
                productDto.setPrice(product.getPrice().doubleValue());
                productDto.setDescription(product.getDescription());
                productDto.setBrand(product.getBrand());
                productDto.setFlavor(product.getFlavor());
                productDto.setImageUrl(product.getImageUrl());
                // Agrega otros campos relevantes si es necesario
                return productDto;
            }).collect(Collectors.toList());
            dto.setProducts(productDtos);

            return dto;
        }).collect(Collectors.toList());
    }

        public List<PaymentPersonalTrainerDTO> getApprovedPersonalTrainerPayments() {
        return paymentRepository.findApprovedPersonalTrainerPayments();
    }





    // PaymentService.java

        public Page<PaymentProductDTO> getApprovedProductPaymentsPage(Pageable pageable) {
            return paymentRepository.findApprovedProductPaymentsPage(pageable);
        }

        public Page<PaymentPlanDTO> getApprovedPlanPaymentsPage(Pageable pageable) {
            return paymentRepository.findApprovedPlanPaymentsPage(pageable);
        }


    
}

