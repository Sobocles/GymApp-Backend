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
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ProductServiceImpl implements ProductService {
    
    private final ProductRepository productRepository;



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

            if (dto.getDiscountStart() != null && !dto.getDiscountStart().isEmpty()) {
            product.setDiscountStart(LocalDateTime.parse(dto.getDiscountStart()));
    }
            if (dto.getDiscountEnd() != null && !dto.getDiscountEnd().isEmpty()) {
                product.setDiscountEnd(LocalDateTime.parse(dto.getDiscountEnd()));
            }

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
        return productRepository.findByActiveTrue();
    }

    @Override
    public Product getProductById(Long id) {
        return productRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Producto no encontrado con ID: " + id));
    }


        @Override
        public Optional<Product> updateProduct(Long id, ProductDto dto, MultipartFile image) {
            // 1. Obtener el producto existente. Si no existe, se lanza una excepción o se retorna Optional.empty().
            Product existingProduct = getProductById(id);
            
            // 2. Actualizar los campos que vienen en el DTO (actualización parcial)
            // Actualización de campos obligatorios (ya validados en el DTO)
            if (dto.getName() != null && !dto.getName().trim().isEmpty()) {
                existingProduct.setName(dto.getName());
            }
            if (dto.getDescription() != null && !dto.getDescription().trim().isEmpty()) {
                existingProduct.setDescription(dto.getDescription());
            }
            if (dto.getPrice() != null) {
                existingProduct.setPrice(BigDecimal.valueOf(dto.getPrice()));
            }
            if (dto.getStock() != null) {
                existingProduct.setStock(dto.getStock());
            }
            if (dto.getBrand() != null && !dto.getBrand().trim().isEmpty()) {
                existingProduct.setBrand(dto.getBrand());
            }
            if (dto.getFlavor() != null && !dto.getFlavor().trim().isEmpty()) {
                existingProduct.setFlavor(dto.getFlavor());
            }
            
            // Actualización de los campos de oferta (opcionales)
            if (dto.getDiscountPercent() != null) {
                existingProduct.setDiscountPercent(dto.getDiscountPercent());
            }
            if (dto.getDiscountReason() != null && !dto.getDiscountReason().trim().isEmpty()) {
                existingProduct.setDiscountReason(dto.getDiscountReason());
            }
            if (dto.getDiscountStart() != null && !dto.getDiscountStart().trim().isEmpty()) {
                try {
                    existingProduct.setDiscountStart(LocalDateTime.parse(dto.getDiscountStart()));
                } catch (Exception e) {
                    throw new IllegalArgumentException("Formato incorrecto en discountStart. Se espera ISO_LOCAL_DATE_TIME.");
                }
            }
            if (dto.getDiscountEnd() != null && !dto.getDiscountEnd().trim().isEmpty()) {
                try {
                    existingProduct.setDiscountEnd(LocalDateTime.parse(dto.getDiscountEnd()));
                } catch (Exception e) {
                    throw new IllegalArgumentException("Formato incorrecto en discountEnd. Se espera ISO_LOCAL_DATE_TIME.");
                }
            }

            // 3. Actualizar la categoría: se asume que en el DTO el campo category se envía como string.
            if (dto.getCategory() != null && !dto.getCategory().trim().isEmpty()) {
                // Buscamos la categoría en base al nombre
                Category categoryEntity = categoryService.getCategoryByName(dto.getCategory());
                if (categoryEntity == null) {
                    throw new IllegalArgumentException("La categoría no existe: " + dto.getCategory());
                }
                existingProduct.setCategory(categoryEntity);
            }
            
            // 4. Actualizar la imagen: si se envía un archivo, se sube y se asigna la nueva URL.
            if (image != null && !image.isEmpty()) {
                try {
                    String imageUrl = cloudinaryService.uploadImage(image);
                    existingProduct.setImageUrl(imageUrl);
                } catch (IOException e) {
                    // Aquí se podría manejar el error de forma más específica.
                    throw new RuntimeException("Error subiendo imagen a Cloudinary", e);
                }
            }
            
            // 5. Guardar y retornar el producto actualizado
            Product savedProduct = productRepository.save(existingProduct);
            return Optional.of(savedProduct);
        }

        @Override
        public void deleteProduct(Long id) {
            Product product = productRepository.findById(id)
               .orElseThrow(() -> new IllegalArgumentException("Producto no encontrado"));
        
            product.setActive(false);
            productRepository.save(product);
        }
        



        public Page<Product> findByCategory(Category category, Pageable pageable) {
            return productRepository.findByCategoryAndActiveTrue(category, pageable);
        }

    @Override
    public Page<Product> findAll(Pageable pageable) {
        return productRepository.findByActiveTrue(pageable);
    }

    @Override
    public List<Product> searchProducts(String term) {
        return productRepository.findByNameContainingIgnoreCaseAndActiveTrue(term);
    }


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
    Specification<Product> spec = Specification.where(ProductSpecification.isActive());

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

@Override
public List<Product> getActiveDiscountProducts() {
    LocalDateTime now = LocalDateTime.now();
    return productRepository.findActiveDiscounts(now);
}

@Override
public List<Product> getMostSoldProducts() {
    return productRepository.findMostSoldProducts();
}



}



