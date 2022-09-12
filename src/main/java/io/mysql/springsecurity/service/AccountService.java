package io.mysql.springsecurity.service;

import io.mysql.springsecurity.entity.AppRole;
import io.mysql.springsecurity.entity.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser editUser(AppUser appUser);
    void deleteUser(String username);
    AppUser showOneUser(String username);
    List<AppUser> showAllUsers();
    List<AppRole> showAllRoles();
}
