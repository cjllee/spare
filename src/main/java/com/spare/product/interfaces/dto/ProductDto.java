package com.spare.product.interfaces.dto;

import com.spare.product.domain.Product;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "제품")
public class ProductDto {

    @Schema(description = "제품 ID", example = "1")
    private Long id;

    @Schema(description = "제품명", example = "조던1")
    private String name;

    @Schema(description = "브랜드", example = "나이키")
    private String brand;

    @Schema(description = "카테고리", example = "신발")
    private String category;

    @Schema(description = "시작가격", example = "1,000")
    private BigDecimal startPrice;

    @Schema(description = "등록일", example = "25-03-27")
    private LocalDateTime createdAt;

    public Product toEntity() {
        return new Product(name, brand, category, startPrice);
    }
}