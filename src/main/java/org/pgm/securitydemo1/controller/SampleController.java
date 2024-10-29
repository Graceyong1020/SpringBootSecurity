package org.pgm.securitydemo1.controller;

import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Log4j2

public class SampleController {
    @GetMapping("/")
    public String home() {
        log.info("home............");
        return "index";
    }
    //@GetMapping("/user/login") //UserController에 login이 있어서 주석처리
    public void login() {
        log.info("login............");
    }
    @GetMapping("/all") //모든 사용자가 접근 가능
    public String exAll() {
        log.info("exAll............");
        return "exAll";
    }
    @GetMapping("/member")
    public void exMember() {
        log.info("exMember............");
    }
    @GetMapping("/admin")
    public void exAdmin() {
        log.info("exAdmin............");
    }
}
