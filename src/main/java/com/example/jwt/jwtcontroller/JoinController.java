package com.example.jwt.jwtcontroller;

import com.example.jwt.dto.JoinDto;
import com.example.jwt.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {

    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String join(JoinDto joinDto){
    joinService.joinProcess(joinDto);
        return "ok";
    }
}
