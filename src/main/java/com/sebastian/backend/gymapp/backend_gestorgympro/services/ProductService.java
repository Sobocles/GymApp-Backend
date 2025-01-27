package com.sebastian.backend.gymapp.backend_gestorgympro.services;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ProductDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ProductFilterDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.data.domain.Page;

public interface ProductService {
    Product createProduct(ProductDto dto, MultipartFile imageFile);


    List<Product> getAllProducts();
    Product getProductById(Long id);
    void deleteProduct(Long id);
    //List<Product> getProductsByCategory(Category category);

    Page<Product> findByCategory(Category category, Pageable pageable);
    Page<Product> findAll(Pageable pageable);
    List<Product> searchProducts(String term);

    //List<Product> getAllProductsSorted(String sortBy);

    List<String> getDistinctBrands();

    List<String> getDistinctFlavors();

    Page<Product> advancedSearch(ProductFilterDto filter, int page, int size, String sortBy);

    List<Product> getActiveDiscountProducts();

    Optional<Product> updateProduct(Long id, ProductDto dto, MultipartFile image);

    List<Product> getMostSoldProducts();



}
