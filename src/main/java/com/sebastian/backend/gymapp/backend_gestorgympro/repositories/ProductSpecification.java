package com.sebastian.backend.gymapp.backend_gestorgympro.repositories;

import java.util.ArrayList;
import java.util.List;

import org.springframework.data.domain.Sort;

import org.springframework.data.jpa.domain.Specification;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;

import jakarta.persistence.criteria.Order;

public class ProductSpecification {

    
          public static Specification<Product> byCategory(String categoryName) {
        return (root, query, criteriaBuilder) -> {
            // asumiendo un root.get("category").get("name")
            return criteriaBuilder.equal(
                root.get("category").get("name"), 
                categoryName
            );
        };
    }

    public static Specification<Product> stockGreaterThan(int stock) {
        return (root, query, criteriaBuilder) ->
            criteriaBuilder.gt(root.get("stock"), stock);
    }

    public static Specification<Product> stockEquals(int stock) {
        return (root, query, criteriaBuilder) ->
            criteriaBuilder.equal(root.get("stock"), stock);
    }

    public static Specification<Product> byFlavors(List<String> flavors) {
        return (root, query, criteriaBuilder) -> root.get("flavor").in(flavors);
    }
    
    public static Specification<Product> byBrands(List<String> brands) {
        return (root, query, criteriaBuilder) -> root.get("brand").in(brands);
    }
    

    public static Specification<Product> priceGreaterThanOrEqualTo(int minPrice) {
        return (root, query, criteriaBuilder) ->
            criteriaBuilder.greaterThanOrEqualTo(root.get("price"), minPrice);
    }

    public static Specification<Product> priceLessThanOrEqualTo(int maxPrice) {
        return (root, query, criteriaBuilder) ->
            criteriaBuilder.lessThanOrEqualTo(root.get("price"), maxPrice);
    }


     public static Specification<Product> withSort(Sort sort) {
        return (root, query, criteriaBuilder) -> {
            if (sort.isSorted()) {
                List<Order> orders = new ArrayList<>();

                // Aplica el ordenamiento a cada campo solicitado
                sort.forEach(order -> {
                    String property = order.getProperty();

                    if (order.isAscending()) {
                        orders.add(criteriaBuilder.asc(root.get(property)));
                    } else {
                        orders.add(criteriaBuilder.desc(root.get(property)));
                    }
                });

                query.orderBy(orders);
            }
            return null;
        };
    }
}
