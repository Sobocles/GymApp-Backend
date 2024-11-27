package com.sebastian.backend.gymapp.backend_gestorgympro.services.mercadoPago;

import com.mercadopago.*;
import com.mercadopago.client.preference.PreferenceClient;
import com.mercadopago.client.preference.PreferenceItemRequest;
import com.mercadopago.client.preference.PreferenceRequest;
import com.mercadopago.client.preference.PreferenceBackUrlsRequest;
import com.mercadopago.exceptions.MPApiException;
import com.mercadopago.exceptions.MPException;
import com.mercadopago.resources.preference.Preference;
import com.mercadopago.client.preference.PreferencePayerRequest;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

import java.math.BigDecimal;
import java.util.Arrays;

@Service
public class MercadoPagoService {

    @Value("${mercadopago.accessToken}")
    private String accessToken;

    @PostConstruct
    public void init() throws MPException {
        System.out.println("Access Token de Mercado Pago: " + accessToken);
        MercadoPagoConfig.setAccessToken(accessToken);
    }

    public Preference createPreference(String title, int quantity, BigDecimal unitPrice, String successUrl, String failureUrl, String pendingUrl, String payerEmail, String externalReference) {
        try {
            PreferenceClient client = new PreferenceClient();
    
            PreferenceItemRequest itemRequest = PreferenceItemRequest.builder()
                    .title(title)
                    .quantity(quantity)
                    .unitPrice(unitPrice)
                    .build();
    
            PreferenceBackUrlsRequest backUrls = PreferenceBackUrlsRequest.builder()
                    .success(successUrl)
                    .failure(failureUrl)
                    .pending(pendingUrl)
                    .build();
    
            // Establecer el email del comprador
            PreferencePayerRequest payerRequest = PreferencePayerRequest.builder()
                    .email(payerEmail)
                    .build();
    
            PreferenceRequest preferenceRequest = PreferenceRequest.builder()
                    .items(Arrays.asList(itemRequest))
                    .backUrls(backUrls)
                    .notificationUrl("https://40e9-2800-150-14e-1f21-d971-aa18-8d35-50ed.ngrok-free.app/payment/notifications")
                    .payer(payerRequest)
                    .externalReference(externalReference)
                    .autoReturn("approved")
                    .build();
    
            Preference preference = client.create(preferenceRequest);
            return preference;
        } catch (MPApiException | MPException e) {
            // Maneja la excepción
            System.err.println("Error al crear la preferencia: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

}
