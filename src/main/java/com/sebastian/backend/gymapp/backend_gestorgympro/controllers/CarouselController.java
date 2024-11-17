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
        return ResponseEntity.ok(images);
    }

}
