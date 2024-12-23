package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;

public interface CategoryRepository extends JpaRepository<Category, Long> {
    Optional<Category> findByName(String name);
    boolean existsByName(String name);
}
