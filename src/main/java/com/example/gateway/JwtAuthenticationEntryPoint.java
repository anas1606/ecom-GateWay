package com.example.gateway;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    private static final long serialVersionUID = -7858869558953243875L;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        ResponseModel rs = new ResponseModel();
        if (response.getStatus() == 400) {
            rs.setMessage("Your account is deactivate");
            rs.setStatusCode(400);
        } else {
            rs.setMessage("Your session is expired. Please Log in again.");
            rs.setStatusCode(401);
        }
        rs.setData(null);
        rs.setStatus(HttpStatus.UNAUTHORIZED);
        response.setContentType("application/json");
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String json = ow.writeValueAsString(rs);

        response.getWriter().write(json);
        response.setStatus(200);
    }

}
