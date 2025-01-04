package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.cloudinary.Cloudinary;
import com.cloudinary.Transformation;
import com.cloudinary.utils.ObjectUtils;

import io.github.cdimascio.dotenv.Dotenv;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.Map;

@Service
public class CloudinaryService {

    private final Cloudinary cloudinary;

    public CloudinaryService() {
        Dotenv dotenv = Dotenv.load();
        String cloudinaryUrl = dotenv.get("CLOUDINARY_URL");
        cloudinary = new Cloudinary(cloudinaryUrl);
    }

    public String uploadImage(MultipartFile file) throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> params = ObjectUtils.asMap(
            "use_filename", true,
            "unique_filename", true,   // Cambiar a true o directamente eliminarlo
            "overwrite", false         // O directamente no setearlo
        );
        
    
        @SuppressWarnings("unchecked")
        Map<String, Object> uploadResult = cloudinary.uploader().upload(file.getBytes(), params);
        return (String) uploadResult.get("secure_url");
    }
    

    public Map<String, Object> getImageDetails(String publicId) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> params = ObjectUtils.asMap(
            "quality_analysis", true
        );
    
        @SuppressWarnings("unchecked")
        Map<String, Object> resourceDetails = cloudinary.api().resource(publicId, params);
        return resourceDetails;
    }
    

    public String getTransformedImageUrl(String publicId) {
        return cloudinary.url()
            .transformation(new Transformation()
                .crop("pad")
                .width(300)
                .height(400)
                .background("auto:predominant"))
            .generate(publicId);
    }

    public void deleteImage(String publicId) throws IOException {
        cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
    }
}
