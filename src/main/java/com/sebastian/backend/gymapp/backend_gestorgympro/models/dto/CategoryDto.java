package com.sebastian.backend.gymapp.backend_gestorgympro.models.dto;

import jakarta.validation.constraints.NotBlank;

public class CategoryDto {

    @NotBlank(message = "El nombre de la categoría no puede estar vacío")
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
