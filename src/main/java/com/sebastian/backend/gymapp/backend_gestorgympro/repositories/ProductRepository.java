package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;


public interface ProductRepository extends JpaRepository<Product, Long>, JpaSpecificationExecutor<Product> {

    Page<Product> findByCategory(Category category, Pageable pageable); 

    List<Product> findByNameContainingIgnoreCase(String name);

    @Query("SELECT p FROM Product p " +
    "LEFT JOIN OrderDetail od ON p.id = od.product.id " +
    "GROUP BY p.id " +
    "ORDER BY SUM(od.quantity) DESC")
    List<Product> findAllOrderBySalesDesc();


    @Query("SELECT DISTINCT p.brand FROM Product p WHERE p.brand IS NOT NULL")
    List<String> findDistinctBrands();

    @Query("SELECT DISTINCT p.flavor FROM Product p WHERE p.flavor IS NOT NULL")
    List<String> findDistinctFlavors();

        @Query("""
           SELECT p 
           FROM Product p
           WHERE p.discountPercent IS NOT NULL 
             AND p.discountPercent > 0
             AND p.discountStart <= :now
             AND p.discountEnd >= :now
           """)
        List<Product> findActiveDiscounts(@Param("now") LocalDateTime now);


        @Query("SELECT p FROM Product p WHERE p.salesCount = (SELECT MAX(p2.salesCount) FROM Product p2)")
        List<Product> findMostSoldProducts();


        

}

