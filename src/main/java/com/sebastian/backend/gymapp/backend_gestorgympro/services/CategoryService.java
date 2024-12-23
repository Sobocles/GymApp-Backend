package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import java.util.List;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;

public interface CategoryService {
    Category createCategory(String name);
    Category getCategoryByName(String name);
    List<Category> getAllCategories();
    Category updateCategory(Long id, String newName);
    void deleteCategory(Long id);
}
