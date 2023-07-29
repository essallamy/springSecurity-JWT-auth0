package com.example.securitedemo.secr.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @Override //quand l'ulisateur va tempter de se d'authentifier
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemptAuthentication");
        String username=request.getParameter("username");
String password=request.getParameter("password");
System.out.println(username);
System.out.println(password);

UsernamePasswordAuthenticationToken authenticationToken=
                        new UsernamePasswordAuthenticationToken(username,password);

        return authenticationManager.authenticate(authenticationToken); // c'est qui va l'appel A UseDetailservice pour recupere les users
    }


    @Override//quand l'authentification a réussir
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        User user = (User) authResult.getPrincipal(); //permet de returner l'utilisateur identifier
        Algorithm algorithm=Algorithm.HMAC256("mySecret123456");
        String jwtAccesToken= JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+1*60*1000))       //5min pour expire
                .withIssuer(request.getRequestURL().toString())     //nom de l'application qui a generer le token
                .withClaim("roles",user.getAuthorities().stream().map(ga->ga.getAuthority()).collect(Collectors.toList())) //list des roles
                .sign(algorithm);
//refresh token pour renouveler le token
        String jwtRefreshToken= JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+15*60*1000))       //15min pour expire
                .withIssuer(request.getRequestURL().toString())     //nom de l'application qui a generer le token
                  .sign(algorithm);
        Map<String,String> idToken=new HashMap<>();
        idToken.put("access-token",jwtAccesToken);
        idToken.put("refresh-token",jwtRefreshToken);

       // response.setHeader("Authorization",jwtAccesToken); // afficher le token en header
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);// afficher le token en objet json
    }
}
