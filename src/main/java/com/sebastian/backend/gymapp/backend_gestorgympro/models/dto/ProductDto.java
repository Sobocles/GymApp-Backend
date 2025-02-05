package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class ProductDto {

    
   @NotBlank
    private String name;

    @NotBlank
    private String description;

    @NotNull
    @Positive
    private Double price;

    private String imageUrl;


    @NotNull
    @PositiveOrZero
    private Integer stock;

    @NotBlank
    private String brand;

    @NotBlank
    private String flavor;
    

    private Integer discountPercent;

    private String discountReason;

    private String discountStart;

    private String discountEnd;


    private String category;

    private String paymentMethod;

    private Long id; 
    private Integer salesCount; 

    public ProductDto() {
    }

    public ProductDto(Long id, String name, Integer salesCount) {
        this.id = id;
        this.name = name;
        this.salesCount = salesCount;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Integer getSalesCount() {
        return salesCount;
    }

    public void setSalesCount(Integer salesCount) {
        this.salesCount = salesCount;
    }



    public String getPaymentMethod() {
        return paymentMethod;
    }
    public void setPaymentMethod(String paymentMethod) {
        this.paymentMethod = paymentMethod;
    }
    public String getImageUrl() {
        return imageUrl;
    }
    public void setImageUrl(String imageUrl) {
        this.imageUrl = imageUrl;
    }
    
    public String getDiscountStart() {
        return discountStart;
    }
    public void setDiscountStart(String discountStart) {
        this.discountStart = discountStart;
    }
    public String getDiscountEnd() {
        return discountEnd;
    }
    public void setDiscountEnd(String discountEnd) {
        this.discountEnd = discountEnd;
    }

    
    public Integer getDiscountPercent() {
        return discountPercent;
    }
    public void setDiscountPercent(Integer discountPercent) {
        this.discountPercent = discountPercent;
    }
    public String getDiscountReason() {
        return discountReason;
    }
    public void setDiscountReason(String discountReason) {
        this.discountReason = discountReason;
    }
    public Integer getStock() {
        return stock;
    }
    public void setStock(Integer stock) {
        this.stock = stock;
    }
    public String getBrand() {
        return brand;
    }
    public void setBrand(String brand) {
        this.brand = brand;
    }
    public String getFlavor() {
        return flavor;
    }
    public void setFlavor(String flavor) {
        this.flavor = flavor;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public String getCategory() {
        return category;
    }
    public void setCategory(String category) {
        this.category = category;
    }
    public Double getPrice() {
        return price;
    }
    public void setPrice(Double price) {
        this.price = price;
    }

}
