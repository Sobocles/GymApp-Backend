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

    @Value("${mercadopago.baseUrl}")
    private String baseUrl;

    private String notificationUrl;


    @PostConstruct
    public void init() throws MPException {

        MercadoPagoConfig.setAccessToken(accessToken);
        this.notificationUrl = baseUrl + "/payment/notifications";
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
                    .notificationUrl(notificationUrl)
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
