package com.spare.user.interfaces.dto.request;

import com.spare.common.validation.ValidationUtil;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.math.BigDecimal;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "제품 생성 요청")
public class CreateProductRequest {

    @NotBlank(message = "제품명은 필수입니다")
    @Size(min = 2, max = 100, message = "제품명은 2자 이상 100자 이하여야 합니다")
    @Schema(description = "제품명", example = "조던1")
    private String name;

    @NotBlank(message = "브랜드는 필수입니다")
    @Size(min = 1, max = 50, message = "브랜드는 1자 이상 50자 이하여야 합니다")
    @Schema(description = "브랜드", example = "나이키")
    private String brand;

    @NotBlank(message = "카테고리는 필수입니다")
    @Size(min = 1, max = 50, message = "카테고리는 1자 이상 50자 이하여야 합니다")
    @Schema(description = "카테고리", example = "신발")
    private String category;

    @NotNull(message = "시작가격은 필수입니다")
    @DecimalMin(value = "0.0", inclusive = false, message = "가격은 0보다 커야 합니다")
    @Schema(description = "시작가격", example = "1000")
    private BigDecimal startPrice;

    public boolean isValid() {
        return ValidationUtil.isValidProductName(name) &&
                ValidationUtil.isValidBrand(brand) &&
                ValidationUtil.isValidCategory(category) &&
                ValidationUtil.isValidPrice(startPrice);
    }

    public void sanitize() {
        this.name = ValidationUtil.sanitizeString(this.name);
        this.brand = ValidationUtil.sanitizeString(this.brand);
        this.category = ValidationUtil.sanitizeString(this.category);
    }
}