package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

public class ProductFilterDto {
    private String category;
    private Boolean inStock;
    private String brand;
    private String flavor;
    private Integer minPrice;
    private Integer maxPrice;

    
    public String getCategory() {
        return category;
    }
    public void setCategory(String category) {
        this.category = category;
    }
    public Boolean getInStock() {
        return inStock;
    }
    public void setInStock(Boolean inStock) {
        this.inStock = inStock;
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
    public Integer getMinPrice() {
        return minPrice;
    }
    public void setMinPrice(Integer minPrice) {
        this.minPrice = minPrice;
    }
    public Integer getMaxPrice() {
        return maxPrice;
    }
    public void setMaxPrice(Integer maxPrice) {
        this.maxPrice = maxPrice;
    }
}
