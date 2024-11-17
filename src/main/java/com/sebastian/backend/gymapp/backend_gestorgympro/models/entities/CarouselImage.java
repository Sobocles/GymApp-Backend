package com.sebastian.backend.gymapp.backend_gestorgympro.models.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "carousel_images")
public class CarouselImage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="image_url", nullable = false)
    private String imageUrl;

    @Column(name="caption")
    private String caption;

    // Cambiar 'order' a 'orderNumber'
    @Column(name="order_number", nullable = false)
    private Integer orderNumber;

    // Constructor vacío
    public CarouselImage() {}

    // Getters y Setters

    public Long getId() {
        return id;
    }

    public String getImageUrl() {
        return imageUrl;
    }

    public String getCaption() {
        return caption;
    }

    public Integer getOrderNumber() {
        return orderNumber;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }

    public void setCaption(String caption) {
        this.caption = caption;
    }

    public void setOrderNumber(Integer orderNumber) {
        this.orderNumber = orderNumber;
    }
}
