package com.spare;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class SpareApplication {
	private static final Logger logger = LoggerFactory.getLogger(SpareApplication.class);

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(SpareApplication.class);
		Environment env = app.run(args).getEnvironment();
		logger.info("Google Client ID: {}", env.getProperty("spring.security.oauth2.client.registration.google.client-id"));
		logger.info("Google Client Secret: {}", env.getProperty("spring.security.oauth2.client.registration.google.client-secret"));
		logger.info("Email Username: {}", env.getProperty("spring.mail.username"));
	}
}