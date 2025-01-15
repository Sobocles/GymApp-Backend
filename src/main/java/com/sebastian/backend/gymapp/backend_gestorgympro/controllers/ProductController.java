package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ProductDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ProductFilterDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProductService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CategoryService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile; 
import org.springframework.http.MediaType;


import java.io.IOException;
import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/store")
public class ProductController {
    
    @Autowired
    private ProductService productService;
    
    @Autowired
    private CloudinaryService cloudinaryService;

    @Autowired
    private CategoryService categoryService;

     @PostMapping(value = "/products", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<?> createProduct(
        @RequestParam("name") String name,
        @RequestParam("description") String description,
        @RequestParam("category") String category,
        @RequestParam("price") Double price,
        @RequestParam("stock") Integer stock,
        @RequestParam("brand") String brand,
        @RequestParam("flavor") String flavor,
        @RequestPart(value = "image", required = false) MultipartFile image
    ) {
        // 1) Crear un DTO con los parámetros
        ProductDto dto = new ProductDto();
        dto.setName(name);
        dto.setDescription(description);
        dto.setCategory(category);
        dto.setPrice(price);
        dto.setStock(stock);
        dto.setBrand(brand);
        dto.setFlavor(flavor);

        try {
            // 2) Llamar al servicio
            Product createdProduct = productService.createProduct(dto, image);
            // 3) Responder OK (200)
            return ResponseEntity.ok(createdProduct);

        } catch (IllegalArgumentException ex) {
            // Por ejemplo, si la categoría no existe
            return ResponseEntity.badRequest().body(ex.getMessage());

        } catch (RuntimeException ex) {
            // Error subiendo imagen o cualquier otra
            return ResponseEntity.status(500)
                                 .body("Error interno al crear producto: " + ex.getMessage());
        }
    }
    

    @GetMapping("/products")
    public ResponseEntity<List<Product>> getAllProducts(@RequestParam(required = false) String category) {
        if (category != null && !category.isEmpty()) {
            // Filtrar por categoría
            Category categoryEntity = categoryService.getCategoryByName(category);
            List<Product> productsByCategory = productService.getProductsByCategory(categoryEntity);
            return ResponseEntity.ok(productsByCategory);
        } else {
            // Sin filtro de categoría
            return ResponseEntity.ok(productService.getAllProducts());
        }
    }

    
    @GetMapping("/products/{id}")
    public ResponseEntity<Product> getProductById(@PathVariable Long id) {
        return ResponseEntity.ok(productService.getProductById(id));
    }

    
    @PutMapping("/products/{id}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Product> updateProduct(
        @PathVariable Long id,
        @RequestParam(required = false) String name,
        @RequestParam(required = false) String description,
        @RequestParam(required = false) String category,
        @RequestParam(required = false) Double price,
        @RequestParam(required = false) Integer stock,
        @RequestParam(required = false) String brand,
        @RequestParam(required = false) String flavor,
        @RequestParam(required = false) MultipartFile image
    ) {
        Product productDetails = productService.getProductById(id);
    
        if (name != null) productDetails.setName(name);
        if (description != null) productDetails.setDescription(description);
        if (price != null) productDetails.setPrice(BigDecimal.valueOf(price));
        if (stock != null) productDetails.setStock(stock);
        if (brand != null) productDetails.setBrand(brand);
        if (flavor != null) productDetails.setFlavor(flavor);
    
        if (category != null) {
            Category categoryEntity = categoryService.getCategoryByName(category);
            productDetails.setCategory(categoryEntity);
        }
    
        if (image != null && !image.isEmpty()) {
            try {
                String imageUrl = cloudinaryService.uploadImage(image);
                productDetails.setImageUrl(imageUrl);
            } catch (IOException e) {
                return ResponseEntity.badRequest().build();
            }
        }
    
        Product updatedProduct = productService.updateProduct(id, productDetails);
        return ResponseEntity.ok(updatedProduct);
    }
    
    

    @DeleteMapping("/products/{id}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Void> deleteProduct(@PathVariable Long id) {
        productService.deleteProduct(id);
        return ResponseEntity.noContent().build();
    }



@GetMapping("/products/page/{page}")
public ResponseEntity<Page<Product>> getProductsPage(
    @PathVariable int page,
    @RequestParam(defaultValue = "12") int size,
    @RequestParam(required = false) String category
) {
    Pageable pageable = PageRequest.of(page, size);
    Page<Product> productPage;

    if (category != null && !category.isEmpty()) {
        Category cat = categoryService.getCategoryByName(category);
        productPage = productService.findByCategory(cat, pageable);
    } else {
        productPage = productService.findAll(pageable);
    }

    return ResponseEntity.ok(productPage);
}

    // ProductController.java
    @GetMapping("/products/search")
    public ResponseEntity<List<Product>> searchProducts(@RequestParam("term") String term) {
        // Por simplicidad, filtramos solo por nombre. Ajusta según tu lógica.
        List<Product> results = productService.searchProducts(term);
        return ResponseEntity.ok(results);
    }

    // ProductController.java

    @GetMapping("/products/sorted")
    public ResponseEntity<List<Product>> getProductsSorted(
        @RequestParam(value = "sortBy", required = false, defaultValue = "price_asc") String sortBy
    ) {
        // Este método delega la lógica a tu servicio
        List<Product> sortedProducts = productService.getAllProductsSorted(sortBy);
        return ResponseEntity.ok(sortedProducts);
    }

    
    @GetMapping("/products/brands")
    public ResponseEntity<List<String>> getDistinctBrands() {
        List<String> brands = productService.getDistinctBrands();
        return ResponseEntity.ok(brands);
    }

    @GetMapping("/products/flavors")
    public ResponseEntity<List<String>> getDistinctFlavors() {
        List<String> flavors = productService.getDistinctFlavors();
        return ResponseEntity.ok(flavors);
    }

    // ProductController.java

    @GetMapping("/products/search2")
    public ResponseEntity<Page<Product>> searchProducts2(
        ProductFilterDto filter,
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "12") int size,
        @RequestParam(defaultValue = "price_asc") String sortBy
    ) {
        System.out.println("Filtros recibidos del frontend: " + filter);
        System.out.println("Ordenamiento: " + sortBy);
    
        Page<Product> productPage = productService.advancedSearch(filter, page, size, sortBy);
        return ResponseEntity.ok(productPage);
    }
    


}
