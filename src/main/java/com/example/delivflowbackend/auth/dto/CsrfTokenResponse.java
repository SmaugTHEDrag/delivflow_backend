package com.example.delivflowbackend.auth.dto;

public record CsrfTokenResponse(String token, String headerName) {
}
