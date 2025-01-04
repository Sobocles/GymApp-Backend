package com.sebastian.backend.gymapp.backend_gestorgympro.controllers;

import com.sebastian.backend.gymapp.backend_gestorgympro.services.CloudinaryService;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.entities.CarouselImage;
import com.sebastian.backend.gymapp.backend_gestorgympro.repositories.CarouselImageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/carousel")
public class CarouselController {

    @Autowired
    private CloudinaryService cloudinaryService;

    @Autowired
    private CarouselImageRepository carouselImageRepository;

    // Otros métodos...

    @PostMapping("/images")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<CarouselImage> addCarouselImage(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "caption", required = false) String caption,
            @RequestParam(value = "order", required = false, defaultValue = "0") Integer orderNumber
    ) {
        try {
            // Sube la imagen a Cloudinary
            String imageUrl = cloudinaryService.uploadImage(file);
    
            // Crear y guardar la entidad CarouselImage
            CarouselImage carouselImage = new CarouselImage();
            carouselImage.setImageUrl(imageUrl);
            carouselImage.setCaption(caption);
            carouselImage.setOrderNumber(orderNumber);
    
            CarouselImage savedImage = carouselImageRepository.save(carouselImage);
    
            return ResponseEntity.ok(savedImage);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).build();
        }
    }

    // Obtener detalles de una imagen (opcional)
    @GetMapping("/images/{publicId}")
    public ResponseEntity<Map<String, Object>> getImageDetails(@PathVariable String publicId) {
        try {
            Map details = cloudinaryService.getImageDetails(publicId);
            return ResponseEntity.ok(details);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).build();
        }
    }

    // Obtener la URL de una imagen transformada (opcional)
    @GetMapping("/images/{publicId}/transformed")
    public ResponseEntity<String> getTransformedImageUrl(@PathVariable String publicId) {
        String url = cloudinaryService.getTransformedImageUrl(publicId);
        return ResponseEntity.ok(url);
    }

    // Obtener todas las imágenes del carrusel
    @GetMapping("/images")
    public ResponseEntity<List<CarouselImage>> getAllCarouselImages() {
        List<CarouselImage> images = carouselImageRepository.findAllByOrderByOrderNumberAsc();
        System.out.println("AQUI LAS IMAGENES:");
        images.forEach(image -> System.out.println(image));

        return ResponseEntity.ok(images);
    }

    // Actualizar una imagen del carrusel
    @PutMapping("/images/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<CarouselImage> updateCarouselImage(
            @PathVariable Long id,
            @RequestParam(value = "file", required = false) MultipartFile file,
            @RequestParam(value = "caption", required = false) String caption,
            @RequestParam(value = "order", required = false) Integer orderNumber) {
        
        Optional<CarouselImage> imageOpt = carouselImageRepository.findById(id);
    
        if (imageOpt.isPresent()) {
            try {
                CarouselImage image = imageOpt.get();
                
                // Si se sube un nuevo archivo, eliminar la imagen anterior de Cloudinary
                if (file != null && !file.isEmpty()) {
                    String publicId = extractPublicIdFromUrl(image.getImageUrl());
                    cloudinaryService.deleteImage(publicId);
                    
                    // Subir la nueva imagen
                    String imageUrl = cloudinaryService.uploadImage(file);
                    image.setImageUrl(imageUrl);
                }
                
                // Actualizar otros campos
                if (caption != null) {
                    image.setCaption(caption);
                }
                if (orderNumber != null) {
                    image.setOrderNumber(orderNumber);
                }
    
                carouselImageRepository.save(image);
                return ResponseEntity.ok(image);
    
            } catch (IOException e) {
                e.printStackTrace();
                return ResponseEntity.status(500).build();
            }
        } else {
            return ResponseEntity.notFound().build();
        }
    }
    

// Eliminar una imagen del carrusel
@DeleteMapping("/images/{id}")
@PreAuthorize("hasRole('ADMIN')")
public ResponseEntity<Void> deleteCarouselImage(@PathVariable Long id) {
    Optional<CarouselImage> imageOpt = carouselImageRepository.findById(id);

    if (imageOpt.isPresent()) {
        try {
            CarouselImage image = imageOpt.get();
            // Obtener el publicId de la URL para eliminarla de Cloudinary
            String publicId = extractPublicIdFromUrl(image.getImageUrl());
            cloudinaryService.deleteImage(publicId);

            carouselImageRepository.deleteById(id);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    } else {
        return ResponseEntity.notFound().build();
    }
}

// Método auxiliar para extraer publicId desde la URL de Cloudinary
private String extractPublicIdFromUrl(String url) {
    String[] parts = url.split("/");
    return parts[parts.length - 1].split("\\.")[0];
}


}
