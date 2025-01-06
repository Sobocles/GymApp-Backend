package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;


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
    public ResponseEntity<Product> createProduct(
        @RequestParam("name") String name,
        @RequestParam("description") String description,
        @RequestParam("category") String category,
        @RequestParam("price") Double price,
        @RequestParam("stock") Integer stock,
        @RequestParam("salesCount") Integer salesCount,
        @RequestPart(value = "image", required = false) MultipartFile image
    ) {
        String imageUrl = null;
        if (image != null && !image.isEmpty()) {
            try {
                imageUrl = cloudinaryService.uploadImage(image);
            } catch (IOException e) {
                return ResponseEntity.badRequest().build();
            }
        }
    
        Category categoryEntity = categoryService.getCategoryByName(category);
        if (categoryEntity == null) {
            return ResponseEntity.badRequest().body(null);
        }
    
        Product product = new Product();
        product.setName(name);
        product.setDescription(description);
        product.setCategory(categoryEntity);
        product.setPrice(BigDecimal.valueOf(price));
        product.setStock(stock);
        product.setSalesCount(salesCount);
        product.setImageUrl(imageUrl);
    
        Product createdProduct = productService.createProduct(product);
        return ResponseEntity.ok(createdProduct);
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
        @RequestParam(required = false) Integer salesCount,
        @RequestParam(required = false) MultipartFile image
    ) {
        Product productDetails = productService.getProductById(id);
    
        if (name != null) productDetails.setName(name);
        if (description != null) productDetails.setDescription(description);
        if (price != null) productDetails.setPrice(BigDecimal.valueOf(price));
        if (stock != null) productDetails.setStock(stock);
        if (salesCount != null) productDetails.setSalesCount(salesCount);
    
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


  /* 
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
*/
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

    @GetMapping("/products/page/{page}")
    public ResponseEntity<Page<Product>> getProductsPage(
        @PathVariable int page,
        @RequestParam(defaultValue = "12") int size,
        @RequestParam(required = false) String category,
        @RequestParam(defaultValue = "price_asc") String sortBy
    ) {
        System.out.println("VALORES QUE LLEGAN DE FRONT-END");
        System.out.println(page);
        System.out.println(size);
        System.out.println(category);
        System.out.println(sortBy);
        System.out.println("----------------------------------");
        Sort sort;
        switch (sortBy) {
            case "best_selling":
            System.out.println("best_selling");
                sort = Sort.by(Sort.Direction.DESC, "salesCount");
                System.out.println("AQUI SORT"+sort);
                break;
            case "price_desc":
            System.out.println("PRICE_DESC");
                sort = Sort.by(Sort.Direction.DESC, "price");
                System.out.println("AQUI SORT"+sort);
                break;
            default:
                System.out.println("PRICE_ASC"); 
                sort = Sort.by(Sort.Direction.ASC, "price");
                System.out.println("AQUI SORT"+sort);
        }
    
        Pageable pageable = PageRequest.of(page, size, sort);
    
        Page<Product> productPage;
        if (category != null && !category.isEmpty()) {
            Category cat = categoryService.getCategoryByName(category);
            productPage = productService.findByCategory(cat, pageable);
        } else {
            productPage = productService.findAll(pageable);
        }
    
        return ResponseEntity.ok(productPage);
    }
    
    




}
