package io.mysql.springsecurity.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mysql.springsecurity.entity.AppRole;
import io.mysql.springsecurity.entity.AppUser;
import io.mysql.springsecurity.service.AccountService;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class Controller {

    private AccountService accountService;

    public Controller(AccountService accountService) {
        this.accountService = accountService;
    }

    @PostMapping("/users")
    public AppUser addNewUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostMapping("/roles")
    AppRole addNewRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping("/roleToUser")
    void addRoleToUser(HttpServletRequest request, HttpServletResponse response) throws Exception{
        accountService.addRoleToUser(request.getParameter("username"),request.getParameter("roleName"));
        new ObjectMapper().writeValue(response.getOutputStream(),"Role Ajouté avec succès");
    }

    @PatchMapping("/users")
    AppUser editUser(@RequestBody AppUser appUser){
        return accountService.editUser(appUser);
    }

    @DeleteMapping("/users")
    void deleteUser(HttpServletRequest request, HttpServletResponse response) throws Exception{
        accountService.deleteUser(request.getParameter("username"));
        new ObjectMapper().writeValue(response.getOutputStream(),"Utilisateur supprimé avec succès");
    }

    @PostMapping("/user")
    AppUser showOneUser(HttpServletRequest request, HttpServletResponse response) throws Exception{
        return accountService.showOneUser(request.getParameter("username"));
    }

    @GetMapping("/users")
    List<AppUser> showAllUsers(){
        return accountService.showAllUsers();
    }

    @GetMapping("/roles")
    List<AppRole> showAllRoles(){
     return accountService.showAllRoles();
    }

    @GetMapping("/refreshToken")
    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String authToken= request.getHeader("Authorization");
        if(authToken!=null && authToken.startsWith("Bearer ")){

            try {
                String jwtRefreshToken=authToken.substring(7);
                Algorithm algorithm=Algorithm.HMAC256("SECRET");
                JWTVerifier jwtVerifier= JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);
                String username=decodedJWT.getSubject();
                AppUser appUser=accountService.showOneUser(username);
                String jwtAccessToken=JWT.create()
                        .withSubject(username)
                        .withIssuer(request.getRequestURL().toString())
                        .withExpiresAt(new Date(System.currentTimeMillis()+5*60*1000))
                        .withClaim("roles",appUser.getAppRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String,String> token = new HashMap<>();
                token.put("AccessToken",jwtAccessToken);
                token.put("RefreshToken", jwtRefreshToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),token);

            }catch (Exception e){
                response.setStatus(403);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),"REFRESH TOKEN INVALIDE");
            }

        }else{
            response.setStatus(403);
            response.setContentType("application/json");
            new ObjectMapper().writeValue(response.getOutputStream(),"REFRESH TOKEN INTROUVABLE");
        }
    }


}
