package com.example.delivflowbackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class DelivflowbackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(DelivflowbackendApplication.class, args);
	}

}
