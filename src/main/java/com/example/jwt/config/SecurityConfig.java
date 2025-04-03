package com.example.jwt.config;

import com.example.jwt.jwt.LoginFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // 이 클래스가 설정(config) 클래스 임을 나타냄
@EnableWebSecurity // Spring Security 설정을 활성화 함
public class SecurityConfig {


    private final AuthenticationConfiguration authenticationConfiguration;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration) {
        this.authenticationConfiguration = authenticationConfiguration;
    }


    @Bean // 비밀번호를 암호화하거나 확인할 때 사용할 인코더 , 회원가입 시 비밀번호를 해싱하는 데 사용됨 , 로그인 시 db에 저장된 해시와 비교함
    public BCryptPasswordEncoder bCryptPasswordEncoder(){

        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }


    @Bean // Spring Security 에서 필터 체인을 설정할 때 사용하는 방식
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        // *csrf 란? = "크로스 사이트 요청 위조" , csrf 는 사용자가 의도하지 않은 요청을 다른 웹사이트가 몰래 보내는 공격

        // 사용자의 세션/쿠키를 위조,악용 해서 의도하지 않은 요청을 보내게 하는 것
        // jwt 토큰을 사용 할 때 csrf 를 비활성화 하는 이유는 세션과 쿠키를 사용한 로그인이 아니라 jwt 토큰을 사용한 로그인 이기 때문에 csrf 가 필요없음


        //csrf disable
        // csrf는 기본적으로 브라우저 기반의 공격 방지,  REST API 에서는 주로 stateless(무상태) 방식이라서 필요 없음 -> 비활성화
        http
                .csrf((auth) -> auth.disable());

        // Form 로그인 방식 disable
        // Spring 기본 로그인 폼 사용 x , 우리는 직접 만든 로그인 로직 + jwt 사용
        http
                .formLogin((auth) -> auth.disable());

        // http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        // 아이디/비밀번호를 http header에 base64 로 보내는 방식 x , 대신 jwt로 인증 처리함
        http
                .authorizeHttpRequests((auth) -> auth // permitAll() = 로그인,메인, 회원가입은 누구나 접근 가능
                        .requestMatchers("/login", "/" , "/join").permitAll() // /admin : ROLE_ADMIN 권한이 있어야 접근 가능
                        .requestMatchers("/admin").hasRole("ADMIN")            // 그 외 나머지 경로는 인증된 사용자만 허용
                        .anyRequest().authenticated());

        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration)), UsernamePasswordAuthenticationFilter.class);


        // 세션 설정
        // jwt는 세션 기반이 아니라 토큰 기반 인증 , 매 요청마다 토큰을 검증하기 때문에 세션을 사용하지 않음
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
