package be.jwt_authentication.repository;

import be.jwt_authentication.models.ERole;
import be.jwt_authentication.models.Role;
import be.jwt_authentication.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}