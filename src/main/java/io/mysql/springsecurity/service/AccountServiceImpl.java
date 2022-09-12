package io.mysql.springsecurity.service;

import io.mysql.springsecurity.entity.AppRole;
import io.mysql.springsecurity.entity.AppUser;
import io.mysql.springsecurity.repository.AppRoleRepository;
import io.mysql.springsecurity.repository.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class AccountServiceImpl implements AccountService {

    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;

    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser appUser) {
        String password=appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(password));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser=appUserRepository.findByUsername(username);
        AppRole appRole=appRoleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }

    @Override
    public AppUser editUser(AppUser appUser) {
        String username=appUser.getUsername();
        AppUser appUser1=appUserRepository.findByUsername(username);
        appUser1.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return appUserRepository.save(appUser1);
    }

    @Override
    public void deleteUser(String username) {
        AppUser appUser=appUserRepository.findByUsername(username);
        appUserRepository.deleteById(appUser.getId());
    }

    @Override
    public AppUser showOneUser(String username) {
        return appUserRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> showAllUsers() {
        return appUserRepository.findAll();
    }

    @Override
    public List<AppRole> showAllRoles() {
        return appRoleRepository.findAll();
    }
}
