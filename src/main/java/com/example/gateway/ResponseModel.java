package com.example.gateway;

import lombok.Data;
import org.springframework.http.HttpStatus;


@Data
public class ResponseModel {
    private HttpStatus status;
    private int statusCode;
    private String message;
    private Object data;
}
