package io.mysql.springsecurity.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mysql.springsecurity.entity.AppRole;
import io.mysql.springsecurity.entity.AppUser;
import io.mysql.springsecurity.service.AccountService;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

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


}
