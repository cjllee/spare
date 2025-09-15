package com.spare.product.application;

import com.spare.product.domain.Product;
import com.spare.product.infrastructure.ProductRepository;
import com.spare.product.interfaces.dto.ProductDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class ProductService {
    private static final Logger logger = LoggerFactory.getLogger(ProductService.class);
    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    public ProductDto createProduct(ProductDto productDto) {
        Product product = productDto.toEntity();
        Product savedProduct = productRepository.save(product);
        logger.info("Product created with ID: {}", savedProduct.getId());
        return new ProductDto(savedProduct.getId(), savedProduct.getName(), savedProduct.getBrand(), savedProduct.getCategory(), savedProduct.getStartPrice(), savedProduct.getCreatedAt());
    }

    public ProductDto getProduct(Long id) {
        Product product = productRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("Product not found"));
        logger.info("Product retrieved with ID: {}", id);
        return new ProductDto(product.getId(), product.getName(), product.getBrand(), product.getCategory(), product.getStartPrice(), product.getCreatedAt());
    }

    public List<ProductDto> getAllProducts() {
        List<Product> products = productRepository.findAll();
        logger.info("Retrieved {} products", products.size());
        return products.stream()
                .map(p -> new ProductDto(p.getId(), p.getName(), p.getBrand(), p.getCategory(), p.getStartPrice(), p.getCreatedAt()))
                .collect(Collectors.toList());
    }

    public ProductDto updateProduct(Long id, ProductDto productDto) {
        Product product = productRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("Product not found"));
        product = new Product(productDto.getName(), productDto.getBrand(), productDto.getCategory(), productDto.getStartPrice());
        Product updatedProduct = productRepository.save(product);
        logger.info("Product updated with ID: {}", id);
        return new ProductDto(updatedProduct.getId(), updatedProduct.getName(), updatedProduct.getBrand(), updatedProduct.getCategory(), updatedProduct.getStartPrice(), updatedProduct.getCreatedAt());
    }

    public void deleteProduct(Long id) {
        productRepository.deleteById(id);
        logger.info("Product deleted with ID: {}", id);
    }
}
