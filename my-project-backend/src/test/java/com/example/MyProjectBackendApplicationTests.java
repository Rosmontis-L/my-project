package com.example;

import com.example.mapper.AccountMapper;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class MyProjectBackendApplicationTests {

    @Resource
    AccountMapper mapper;

    @Test
    void contextLoads() {
        System.out.println(mapper.selectById(1));
    }

}
