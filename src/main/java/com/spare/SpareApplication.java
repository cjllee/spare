package com.spare;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//
@SpringBootApplication
public class SpareApplication {
	private static final Logger logger = LoggerFactory.getLogger(SpareApplication.class);

	public static void main(String[] args) {
		logger.info("Spare application starting...");
		SpringApplication.run(SpareApplication.class, args);
		logger.debug("Debug log test for Day 2");
	}
}