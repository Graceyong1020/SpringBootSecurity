package org.pgm.securitydemo1.service;

import org.pgm.securitydemo1.domain.Board;
import org.pgm.securitydemo1.domain.User;

import java.util.List;

public interface BoardService {
    void insert(Board board, User user);
    public List<Board> list();
    public Board findById(Long bno);
    public void update(Board board);
    public void delete(Long num);
}
