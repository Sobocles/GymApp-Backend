// src/main/java/com/sebastian/backend/gymapp/backend_gestorgympro/models/dto/PaymentProductDTO.java

package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;

public class PaymentProductDTO {
    private Long paymentId;
    private String username;
    private String paymentMethod;
    private LocalDateTime paymentDate;
    private BigDecimal transactionAmount;
    private String productName;

    // Constructor requerido por JPQL
    public PaymentProductDTO(Long paymentId, String username, String paymentMethod, 
                             LocalDateTime paymentDate, BigDecimal transactionAmount, 
                             String productName) {
        this.paymentId = paymentId;
        this.username = username;
        this.paymentMethod = paymentMethod;
        this.paymentDate = paymentDate;
        this.transactionAmount = transactionAmount;
        this.productName = productName;
    }

    // Getters y Setters
    public Long getPaymentId() {
        return paymentId;
    }
    public void setPaymentId(Long paymentId) {
        this.paymentId = paymentId;
    }
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public String getPaymentMethod() {
        return paymentMethod;
    }
    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }
    public LocalDateTime getPaymentDate() {
        return paymentDate;
    }
    public void setPaymentDate(LocalDateTime paymentDate) {
        this.paymentDate = paymentDate;
    }
    public BigDecimal getTransactionAmount() {
        return transactionAmount;
    }
    public void setTransactionAmount(BigDecimal transactionAmount) {
        this.transactionAmount = transactionAmount;
    }
    public String getProductName() {
        return productName;
    }
    public void setProductName(String productName) {
        this.productName = productName;
    }
}
