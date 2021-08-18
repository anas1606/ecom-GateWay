package com.example.gateway;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.access.AccessDeniedHandler;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class RestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest hsr, HttpServletResponse hsr1, org.springframework.security.access.AccessDeniedException ade) throws IOException, ServletException {
        ResponseModel rs = new ResponseModel();
        rs.setData(null);
        rs.setMessage("Unauthorized Request");
        rs.setStatus(HttpStatus.UNAUTHORIZED);
        rs.setStatusCode(401);
        hsr1.setContentType("application/json");
        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String json = ow.writeValueAsString(rs);

        hsr1.getWriter().write(json);
        hsr1.setStatus(200);

    }
}
