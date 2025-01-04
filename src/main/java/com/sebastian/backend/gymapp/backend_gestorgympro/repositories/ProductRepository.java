package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;


public interface ProductRepository extends JpaRepository<Product, Long> {

    Page<Product> findByCategory(Category category, Pageable pageable); 

    List<Product> findByNameContainingIgnoreCase(String name);

    @Query("SELECT p FROM Product p LEFT JOIN OrderDetail od ON p.id = od.product.id " +
       "GROUP BY p.id " +
       "ORDER BY COUNT(od.id) DESC")
        List<Product> findAllOrderBySalesDesc();



}

