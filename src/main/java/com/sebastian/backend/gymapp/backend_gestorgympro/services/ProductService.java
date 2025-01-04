package com.sebastian.backend.gymapp.backend_gestorgympro.services;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Page;

public interface ProductService {
    Product createProduct(Product product);
    List<Product> getAllProducts();
    Product getProductById(Long id);
    Product updateProduct(Long id, Product product);
    void deleteProduct(Long id);
    List<Product> getProductsByCategory(Category category);

    Page<Product> findByCategory(Category category, Pageable pageable);
    Page<Product> findAll(Pageable pageable);
    List<Product> searchProducts(String term);

    List<Product> getAllProductsSorted(String sortBy);

}
