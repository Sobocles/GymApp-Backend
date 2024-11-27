package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;

import java.math.BigDecimal;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "plans")
public class Plan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Integer getDiscount() {
        return discount;
    }

    public void setDiscount(Integer discount) {
        this.discount = discount;
    }

    private String name; // Ejemplo: "Mensual", "Trimestral", "Anual"

    private BigDecimal price; // Precio del plan

    private String description;

    @Column(nullable = true)
    private Integer discount; // Porcentaje de descuento

    // Un Plan tiene muchos Payment. Un Payment pertenece a un Plan.
    @OneToMany(mappedBy = "plan")
    @JsonIgnore
    private List<Payment> payments;
    
    // Relación uno a muchos con Subscription
    @OneToMany(mappedBy = "plan")
    @JsonIgnore 
    private List<Subscription> subscriptions;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public  BigDecimal getPrice() {
        return price;
    }

    public void setPrice( BigDecimal price) {
        this.price = price;
    }

    public List<Payment> getPayments() {
        return payments;
    }

    public void setPayments(List<Payment> payments) {
        this.payments = payments;
    }

    public List<Subscription> getSubscriptions() {
        return subscriptions;
    }

    public void setSubscriptions(List<Subscription> subscriptions) {
        this.subscriptions = subscriptions;
    }





    // Constructores, getters y setters...
}
