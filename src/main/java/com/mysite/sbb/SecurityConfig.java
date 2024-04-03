package com.mysite.sbb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 모바일 장치에서의 접근을 차단하는 필터를 추가합니다.
            .addFilterBefore(new MobileDeviceDenyFilter(), ChannelProcessingFilter.class)
            .authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
                // 모든 요청에 대해 접근을 허용합니다.
                .requestMatchers(new AntPathRequestMatcher("/**")).permitAll())
            .csrf((csrf) -> 
                // "/h2-console/**" 경로의 요청에 대해 CSRF 보호를 무시합니다.
                csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
            .headers((headers) -> headers.addHeaderWriter(
                // X-Frame-Options 헤더를 설정하여 클릭재킹 공격을 방지합니다.
                new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN)))
            .formLogin((formLogin) -> 
                // 로그인 페이지와 로그인 성공 시 리다이렉트될 페이지를 설정합니다.
                formLogin.loginPage("/user/login").defaultSuccessUrl("/"))
            .logout((logout) -> 
                // 로그아웃 요청 처리자, 로그아웃 성공 시 리다이렉트될 페이지, 세션 무효화 설정을 합니다.
                logout.logoutRequestMatcher(new AntPathRequestMatcher("/user/logout"))
                    .logoutSuccessUrl("/").invalidateHttpSession(true))
            .exceptionHandling()
            // 인증 예외가 발생했을 때의 처리를 정의합니다. 여기서는 "/error" 페이지로 리다이렉트합니다.
            .authenticationEntryPoint((request, response, authException) -> {
                response.sendRedirect("/error");
            });
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        // 비밀번호 인코더를 빈으로 등록합니다.
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        // 인증 매니저를 빈으로 등록합니다.
        return authenticationConfiguration.getAuthenticationManager();
    }
}

