package com.spare.common.exception.product;

import com.spare.common.exception.BusinessException;

public class ProductException extends BusinessException {

    public ProductException(String message) {
        super("PRODUCT_ERROR", message);
    }

    public static class ProductNotFoundException extends ProductException {
        public ProductNotFoundException() {
            super("제품을 찾을 수 없습니다");
        }
    }
}
