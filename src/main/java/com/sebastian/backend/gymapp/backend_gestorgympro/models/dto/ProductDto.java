package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class ProductDto {
    private String name;
    private String description;
    private String category;
    private Double price;
    private Integer stock;
    private String brand;
    private String flavor;
    private Integer discountPercent;
    private String discountReason;
    private String discountStart;  // "2025-04-01T12:00"
    
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
    private String discountEnd; 
    
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
