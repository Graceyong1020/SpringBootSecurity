package org.pgm.securitydemo1.repository;

import org.pgm.securitydemo1.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username); //findByUsername() 메서드를 이용하여 사용자 정보를 조회
    //select * from user where username = ? 와 같은 쿼리가 실행됨
}
