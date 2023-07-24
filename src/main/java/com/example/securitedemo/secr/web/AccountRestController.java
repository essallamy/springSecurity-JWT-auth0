package com.example.securitedemo.secr.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.securitedemo.secr.entities.AppRole;
import com.example.securitedemo.secr.entities.AppUser;
import com.example.securitedemo.secr.service.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    @Autowired
    private AccountService accountService;

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser addNewUser(@RequestBody AppUser appUser) {
        return accountService.addNewUser(appUser);
    }
    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole addNewRole(@RequestBody AppRole appRole) {
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUsers")
    public void addRoleToUser(@RequestBody RoleToUser tgggg) {
        accountService.addRoleToUser(tgggg.getUserName(), tgggg.getRoleName());
    }



    public AppUser loadUserByUsername(String userName) {
        return accountService.loadUserByUsername(userName);
    }
@GetMapping(path="/users")
@PostAuthorize("hasAuthority('USER')")
    public List<AppUser> listeUsers() {
        return accountService.listeUsers();
    }

@GetMapping(path = "/refreshToken")
public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
 String authToken=request.getHeader("Authorization");
 if(authToken!=null && authToken.startsWith("Bearer ")){
     try {
         String refreshToken = authToken.substring(7);
         Algorithm algorithm = Algorithm.HMAC256("mySecret123456");
         JWTVerifier jwtVerifier = JWT.require(algorithm).build();  //

         DecodedJWT decodedJWT = jwtVerifier.verify(refreshToken); // verifier le JWT et returner une variable de type DecodedJWT(DecodedJWT : il contient le contenu (username ;les roles)=>les Claims)

         String username = decodedJWT.getSubject();
         AppUser appUser=accountService.loadUserByUsername(username);

         String jwtAccesToken= JWT.create()
                 .withSubject(appUser.getUserName())
                 .withExpiresAt(new Date(System.currentTimeMillis()+5*60*1000))       //5min pour expire
                 .withIssuer(request.getRequestURL().toString())     //nom de l'application qui a generer le token
                 .withClaim("roles",appUser.getAppRoles().stream().map(ga->ga.getRoleName()).collect(Collectors.toList()))
                 .sign(algorithm);

         Map<String,String> idToken=new HashMap<>();
         idToken.put("access-token",jwtAccesToken);
         idToken.put("refresh-token",refreshToken);

         // response.setHeader("Authorization",jwtAccesToken); // afficher le token en header
         response.setContentType("application/json");
         new ObjectMapper().writeValue(response.getOutputStream(),idToken);// afficher le token en objet json

     }catch(Exception e){

         response.setHeader("error message",e.getMessage());
         response.sendError(HttpServletResponse.SC_FORBIDDEN);  //ERROR 403


     }
 }else{
     throw new RuntimeException("Refresh token required!!!");
 }
}


}

class RoleToUser{
    private String userName;

    private String roleName;

    public RoleToUser(String userName, String roleName) {
        this.userName = userName;
        this.roleName = roleName;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }
}
