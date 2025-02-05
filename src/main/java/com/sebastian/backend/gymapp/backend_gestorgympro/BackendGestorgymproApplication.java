package com.sebastian.backend.gymapp.backend_gestorgympro;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class BackendGestorgymproApplication {

	public static void main(String[] args) {
		SpringApplication.run(BackendGestorgymproApplication.class, args);
	}

}
