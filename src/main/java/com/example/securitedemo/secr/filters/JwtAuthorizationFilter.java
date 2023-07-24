package com.example.securitedemo.secr.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request,response);
        }else {

            String authorizationToken=request.getHeader("Authorization");
            if(authorizationToken!=null && authorizationToken.startsWith("Bearer ")){
                try{

                    String jwt=authorizationToken.substring(7);
                    Algorithm algorithm=Algorithm.HMAC256("mySecret123456");
                    JWTVerifier jwtVerifier= JWT.require(algorithm).build();  //

                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt); // verifier le JWT et returner une variable de type DecodedJWT(DecodedJWT : il contient le contenu (username ;les roles)=>les Claims)

                    String username=decodedJWT.getSubject();
                    String[] roles=decodedJWT.getClaim("roles").asArray(String.class);

                    Collection<GrantedAuthority> authorities=new ArrayList<>();  //pour les roles
                    for(String r:roles){
                        authorities.add(new SimpleGrantedAuthority(r));
                    }
                    UsernamePasswordAuthenticationToken authenticationToken=
                            new UsernamePasswordAuthenticationToken(username,null,authorities);

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken); // pour authentifier le user

                    filterChain.doFilter(request,response); // pour pass a la filter suivant
                }catch(Exception e){
                    response.setHeader("error message",e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);  //ERROR 403

                }


            }else{
                filterChain.doFilter(request,response); // pour pass a la filter suivant
            }

        }


    }
}
