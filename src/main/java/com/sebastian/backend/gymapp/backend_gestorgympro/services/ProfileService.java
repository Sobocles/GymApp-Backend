package com.sebastian.backend.gymapp.backend_gestorgympro.services;

import com.sebastian.backend.gymapp.backend_gestorgympro.models.dto.UserDto;
import com.sebastian.backend.gymapp.backend_gestorgympro.models.request.UserRequest;

import org.springframework.web.multipart.MultipartFile;

public interface ProfileService {


    UserDto updateProfile(UserRequest userRequest, MultipartFile file, String currentEmail);
}
