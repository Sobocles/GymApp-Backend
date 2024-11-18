package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.*;
import java.util.List;

@Entity
@Table(name = "plans")
public class Plan {

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

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
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

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name; // Ejemplo: "Mensual", "Trimestral", "Anual"

    private Double price; // Precio del plan

    // Un Plan tiene muchos Payment. Un Payment pertenece a un Plan.
    @OneToMany(mappedBy = "plan")
    private List<Payment> payments;

    // Relación uno a muchos con Subscription
    @OneToMany(mappedBy = "plan")
    private List<Subscription> subscriptions;

    // Constructores, getters y setters...
}
