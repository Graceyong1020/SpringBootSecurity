package org.pgm.securitydemo1.repository;

import org.pgm.securitydemo1.domain.Board;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BoardRepository extends JpaRepository<Board, Long> {

}
