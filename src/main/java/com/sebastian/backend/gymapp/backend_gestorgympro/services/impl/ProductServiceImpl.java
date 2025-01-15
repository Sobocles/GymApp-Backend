package com.sebastian.backend.gymapp.backend_gestorgympro.services.impl;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ProductDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.ProductFilterDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Category;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.Product;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.ProductRepository;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.ProductSpecification;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CategoryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.services.ProductService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.List;

@Service
public class ProductServiceImpl implements ProductService {
    
    private final ProductRepository productRepository;

    private ProductSpecification productSpecification;

     @Autowired
    private CategoryService categoryService;

    @Autowired
    private CloudinaryService cloudinaryService;

    public ProductServiceImpl(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @Override
    public Product createProduct(ProductDto dto, MultipartFile imageFile) {
        try {
            // 1) Buscar categoría
            Category categoryEntity = categoryService.getCategoryByName(dto.getCategory());
            if (categoryEntity == null) {
                // Podrías lanzar una excepción custom o IllegalArgumentException:
                throw new IllegalArgumentException("La categoría no existe: " + dto.getCategory());
            }

            // 2) Subir imagen (si existe)
            String imageUrl = null;
            if (imageFile != null && !imageFile.isEmpty()) {
                imageUrl = cloudinaryService.uploadImage(imageFile);
            }

            // 3) Construir la entidad Product
            Product product = new Product();
            product.setName(dto.getName());
            product.setDescription(dto.getDescription());
            product.setCategory(categoryEntity);
            product.setPrice(BigDecimal.valueOf(dto.getPrice()));
            product.setStock(dto.getStock());
            product.setBrand(dto.getBrand());
            product.setFlavor(dto.getFlavor());
            product.setImageUrl(imageUrl);

            // Si no está seteado, inicializamos salesCount
            if (product.getSalesCount() == null) {
                product.setSalesCount(0);
            }

            // 4) Guardar y retornar
            return productRepository.save(product);

        } catch (IOException e) {
            // Error subiendo archivo
            throw new RuntimeException("Error subiendo imagen a Cloudinary", e);
        }
    }



    @Override
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    @Override
    public Product getProductById(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Producto no encontrado con ID: " + id));
    }

    @Override
    public Product updateProduct(Long id, Product productDetails) {
        Product product = getProductById(id);
    
        // Actualizar los campos
        if (productDetails.getName() != null) product.setName(productDetails.getName());
        if (productDetails.getDescription() != null) product.setDescription(productDetails.getDescription());
        if (productDetails.getPrice() != null) product.setPrice(productDetails.getPrice());
        if (productDetails.getCategory() != null) product.setCategory(productDetails.getCategory());
        if (productDetails.getBrand() != null) product.setBrand(productDetails.getBrand()); // Actualizar marca
        if (productDetails.getFlavor() != null) product.setFlavor(productDetails.getFlavor()); // Actualizar sabor
        if (productDetails.getImageUrl() != null) product.setImageUrl(productDetails.getImageUrl());
    
        // Guardar el producto actualizado
        return productRepository.save(product);
    }
    

    @Override
    public void deleteProduct(Long id) {
        Product product = getProductById(id);
        productRepository.delete(product);
    }

    @Override
    public List<Product> getProductsByCategory(Category category) {
        return productRepository.findByCategory(category);
    }

    @Override
    public Page<Product> findByCategory(Category category, Pageable pageable) {
        return productRepository.findByCategory(category, pageable);
    }

    @Override
    public Page<Product> findAll(Pageable pageable) {
        return productRepository.findAll(pageable);
    }

        @Override
    public List<Product> searchProducts(String term) {
        // Ejemplo sencillo usando un método finder en el repositorio
        return productRepository.findByNameContainingIgnoreCase(term);
    }
/* 
    @Override
    public List<Product> getAllProductsSorted(String sortBy) {
        switch (sortBy) {
            case "best_selling":

            return productRepository.findAllOrderBySalesDesc();
    
            case "price_desc":
                // De mayor a menor
                return productRepository.findAll(org.springframework.data.domain.Sort.by(
                        org.springframework.data.domain.Sort.Direction.DESC,
                        "price"
                ));
    
            case "price_asc":
            default:
                // De menor a mayor
                return productRepository.findAll(org.springframework.data.domain.Sort.by(
                        org.springframework.data.domain.Sort.Direction.ASC,
                        "price"
                ));
        }
    }

    
   */ 

   public List<String> getDistinctBrands() {
    return productRepository.findDistinctBrands();
}

public List<String> getDistinctFlavors() {
    return productRepository.findDistinctFlavors();
}

@Override
public Page<Product> advancedSearch(ProductFilterDto filter, int page, int size, String sortBy) {

    Sort sort = parseSort(sortBy);  // Obtener ordenamiento por precio o ventas
    Pageable pageable = PageRequest.of(page, size, sort);  // Sin ordenar en paginación
    Specification<Product> spec = Specification.where(null);

    System.out.println("=== Iniciando advancedSearch ===");
    System.out.println("Filtros recibidos: " + filter);
    System.out.println("Página: " + page + ", Tamaño: " + size + ", Orden: " + sortBy);

    // Filtro por categoría
    if (filter.getCategory() != null && !filter.getCategory().isEmpty()) {
        spec = spec.and(ProductSpecification.byCategory(filter.getCategory()));
        System.out.println("Filtro por categoría: " + filter.getCategory());
    }

    // Filtro por existencia (stock)
    if (filter.getInStock() != null) {
        if (filter.getInStock()) {
            spec = spec.and(ProductSpecification.stockGreaterThan(0));
            System.out.println("Filtro por stock > 0 (En existencia)");
        }
        // Si inStock es false, no aplicar filtro de stock.
    }
    

    if (filter.getFlavors() != null && !filter.getFlavors().isEmpty()) {
        spec = spec.and(ProductSpecification.byFlavors(filter.getFlavors()));
        System.out.println("Filtro por sabores: " + filter.getFlavors());
    }
    
    if (filter.getBrands() != null && !filter.getBrands().isEmpty()) {
        spec = spec.and(ProductSpecification.byBrands(filter.getBrands()));
        System.out.println("Filtro por marcas: " + filter.getBrands());
    }
    
    

    // Filtro por rango de precios
    if (filter.getMinPrice() != null) {
        spec = spec.and(ProductSpecification.priceGreaterThanOrEqualTo(filter.getMinPrice()));
        System.out.println("Filtro por precio mínimo: " + filter.getMinPrice());
    }
    if (filter.getMaxPrice() != null) {
        spec = spec.and(ProductSpecification.priceLessThanOrEqualTo(filter.getMaxPrice()));
        System.out.println("Filtro por precio máximo: " + filter.getMaxPrice());
    }

    System.out.println("Especificación final construida: " + spec);

    // Ejecutar consulta con filtros y ordenamiento
    Page<Product> result = productRepository.findAll(spec, pageable);
    System.out.println("Productos encontrados: " + result.getTotalElements());
    System.out.println("Total de páginas: " + result.getTotalPages());

    return result;
}

private Sort parseSort(String sortBy) {
    System.out.println("Parseando orden por: " + sortBy);
    switch (sortBy) {
      case "best_selling":
        System.out.println("Ordenando por ventas (desc)");
        return Sort.by(Sort.Direction.DESC, "salesCount");
      case "price_desc":
        System.out.println("Ordenando por precio descendente");
        return Sort.by(Sort.Direction.DESC, "price");
      case "price_asc":
      default:
        System.out.println("Ordenando por precio ascendente");
        return Sort.by(Sort.Direction.ASC, "price");
    }
}


}



