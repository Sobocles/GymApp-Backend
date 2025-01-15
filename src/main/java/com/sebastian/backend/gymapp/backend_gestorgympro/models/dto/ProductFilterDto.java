package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import java.util.List;

public class ProductFilterDto {
    private String category;
    private Boolean inStock;
    private Integer minPrice;
    private Integer maxPrice;
    private List<String> brands;
    
    public List<String> getBrands() {
        return brands;
    }
    public void setBrands(List<String> brands) {
        this.brands = brands;
    }
    public List<String> getFlavors() {
        return flavors;
    }
    public void setFlavors(List<String> flavors) {
        this.flavors = flavors;
    }
    private List<String> flavors;

    
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
