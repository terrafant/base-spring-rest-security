package com.uay.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
public class HomeController {

    @RequestMapping("/")
    @ResponseBody
    public Map<String, String> home() {
        Map<String, String> model = new HashMap<>();
        model.put("Data", "You can see information available to everyone");
        return model;
    }

    @RequestMapping("check")
    @ResponseBody
    public Dto check(Model model) {
        return new Dto("You can see secured information");
    }

    public class Dto {
        private final String data;

        public Dto(String data) {
            this.data = data;
        }

        public String getData() {
            return data;
        }
    }
}
