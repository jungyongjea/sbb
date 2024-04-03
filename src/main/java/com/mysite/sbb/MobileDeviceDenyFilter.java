package com.mysite.sbb;

import java.io.IOException;
import java.util.regex.Pattern;

import javax.naming.AuthenticationException;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class MobileDeviceDenyFilter extends OncePerRequestFilter {
    // 모바일 장치를 식별하는 패턴을 정의합니다.
    private static final Pattern MOBILE_PATTERN = Pattern.compile(".*(iphone|ipod|ipad|android).*", Pattern.CASE_INSENSITIVE);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String userAgent = request.getHeader("User-Agent");
        String requestURL = request.getRequestURL().toString();

        try {
            // "User-Agent"가 모바일 장치를 나타내고, 요청 URL이 로그인 페이지인지 확인합니다.
            if (userAgent != null && MOBILE_PATTERN.matcher(userAgent).matches() && requestURL.contains("/user/login")) {
                throw new AuthenticationException("Mobile access is not allowed for login page") {};
            }
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            // handle the exception, e.g., log it or redirect to error page
        }
    }
}
