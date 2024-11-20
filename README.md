# Best Practices for Spring Security

This guide covers essential best practices to enhance security in your Spring Boot applications:

- **Password Encoding**: Use strong encoding mechanisms like `BCrypt` to securely store sensitive information.
- **CORS Security**: Restrict cross-origin requests by configuring specific allowed origins to prevent unauthorized access.
- **JWT Implementation**:
  - Utilize **Access Tokens** and **Refresh Tokens** for secure and efficient user authentication.
  - Store tokens securely in memory to reduce exposure to potential attacks.
- **RSA Key Pair**: Leverage **Asymmetric Encryption** with an RSA key pair for secure JWT token signatures, ensuring integrity and authenticity.

# Example code

Source Tree:
```
MarketMaster-Backend
├── Dockerfile
├── pom.xml
└── src
    └── main
        ├── java
        │   └── tn
        │       └── zeros
        │           └── marketmaster
        │               ├── config
        │               │   ├── AuthConfig.java
        │               │   ├── CorsConfig.java
        │               │   └── SecurityConfig.java
        │               ├── controller
        │               │   └── AuthController.java
        │               ├── dto
        │               │   ├── LoginRequestDTO.java
        │               │   ├── RefreshTokenRequestDTO.java
        │               │   ├── SignupRequestDTO.java
        │               │   └── TokenResponseDTO.java
        │               ├── entity
        │               │   ├── enums
        │               │   │   └── Role.java
        │               │   └── User.java
        │               ├── exception
        │               │   ├── CustomAuthenticationException.java
        │               │   ├── TokenValidationException.java
        │               │   └── UserAlreadyExistsException.java
        │               ├── MarketMasterApplication.java
        │               ├── repository
        │               │   └── UserRepository.java
        │               ├── security
        │               │   └── JwtAuthenticationFilter.java
        │               ├── service
        │               │   ├── AuthenticationService.java
        │               │   ├── JwtTokenService.java
        │               │   ├── TokenStorageService.java
        │               │   ├── UserDetailsServiceImpl.java
        │               │   └── UserService.java
        │               └── util
        │                   ├── KeyGeneratorUtility.java
        │                   └── RSAKeyProperties.java
        └── resources
            ├── application.properties
            ├── static
            └── templates
    
```

`pom.xml`:

```````xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>3.3.4</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>tn.ZeroS</groupId>
	<artifactId>MarketMaster</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>MarketMaster</name>
	<description>MarketMaster</description>
	<url/>
	<licenses>
		<license/>
	</licenses>
	<developers>
		<developer/>
	</developers>
	<scm>
		<connection/>
		<developerConnection/>
		<tag/>
		<url/>
	</scm>
	<properties>
		<java.version>17</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-data-jpa</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>com.mysql</groupId>
			<artifactId>mysql-connector-j</artifactId>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>org.projectlombok</groupId>
			<artifactId>lombok</artifactId>
			<optional>true</optional>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.security</groupId>
			<artifactId>spring-security-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-validation</artifactId>
		</dependency>
		<dependency>
			<groupId>me.paulschwarz</groupId>
			<artifactId>spring-dotenv</artifactId>
			<version>4.0.0</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-api</artifactId>
			<version>0.11.5</version>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-impl</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
		<dependency>
			<groupId>io.jsonwebtoken</groupId>
			<artifactId>jjwt-jackson</artifactId>
			<version>0.11.5</version>
			<scope>runtime</scope>
		</dependency>
	</dependencies>

	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<configuration>
					<excludes>
						<exclude>
							<groupId>org.projectlombok</groupId>
							<artifactId>lombok</artifactId>
						</exclude>
					</excludes>
				</configuration>
			</plugin>
		</plugins>
	</build>

</project>

```````

`config\AuthConfig.java`:

```````java
package tn.zeros.marketmaster.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class AuthConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```````

`config\CorsConfig.java`:

```````java
package tn.zeros.marketmaster.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class CorsConfig {
    @Value("${frontend.origin}")
    private String frontendOrigin;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(frontendOrigin)); // Adjust as needed
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```````

`config\SecurityConfig.java`:

```````java
package tn.zeros.marketmaster.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tn.zeros.marketmaster.security.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendError(401, "Unauthorized");
                        })
                );

        return http.build();
    }
}
```````

`controller\AuthController.java`:

```````java
package tn.zeros.marketmaster.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import tn.zeros.marketmaster.dto.LoginRequestDTO;
import tn.zeros.marketmaster.dto.SignupRequestDTO;
import tn.zeros.marketmaster.dto.TokenResponseDTO;
import tn.zeros.marketmaster.dto.RefreshTokenRequestDTO;
import tn.zeros.marketmaster.entity.User;
import tn.zeros.marketmaster.exception.CustomAuthenticationException;
import tn.zeros.marketmaster.exception.TokenValidationException;
import tn.zeros.marketmaster.exception.UserAlreadyExistsException;
import tn.zeros.marketmaster.service.AuthenticationService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@Valid @RequestBody SignupRequestDTO signupRequest) {
        log.info("Attempting signup for user: {}", signupRequest.getEmail());
        User user = authenticationService.signup(signupRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDTO> login(@Valid @RequestBody LoginRequestDTO loginRequest) {
        log.info("Attempting login for user: {}", loginRequest.getUsername());
        TokenResponseDTO tokenResponse = authenticationService.authenticate(loginRequest);
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<TokenResponseDTO> refreshToken(@Valid @RequestBody RefreshTokenRequestDTO refreshTokenRequest) {
        log.info("Attempting to refresh token");
        TokenResponseDTO tokenResponse = authenticationService.refreshToken(refreshTokenRequest.getRefreshToken());
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String token) {
        String username = authenticationService.getUsernameFromToken(token);
        authenticationService.logout(username);
        return ResponseEntity.ok().build();
    }

    @ExceptionHandler(CustomAuthenticationException.class)
    public ResponseEntity<String> handleAuthenticationException(CustomAuthenticationException e) {
        log.error("Authentication error: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }

    @ExceptionHandler(TokenValidationException.class)
    public ResponseEntity<String> handleTokenValidationException(TokenValidationException e) {
        log.error("Token validation error: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<String> handleUserAlreadyExistsException(UserAlreadyExistsException e) {
        log.error("User registration error: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGenericException(Exception e) {
        log.error("Unexpected error: ", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred");
    }
}
```````

`dto\LoginRequestDTO.java`:

```````java
package tn.zeros.marketmaster.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequestDTO {
    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Password is required")
    private String password;
}
```````

`dto\RefreshTokenRequestDTO.java`:

```````java
package tn.zeros.marketmaster.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RefreshTokenRequestDTO {
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
```````

`dto\SignupRequestDTO.java`:

```````java
package tn.zeros.marketmaster.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignupRequestDTO {
    @NotBlank(message = "First name is required")
    private String firstName;

    @NotBlank(message = "Last name is required")
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String password;
}
```````

`dto\TokenResponseDTO.java`:

```````java
package tn.zeros.marketmaster.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenResponseDTO {
    private String accessToken;
    private String refreshToken;
}
```````

`entity\enums\Role.java`:

```````java
package tn.zeros.marketmaster.entity.enums;

import lombok.Getter;

@Getter
public enum Role {
    USER,
    ADMIN
}
```````

`entity\User.java`:

```````java
package tn.zeros.marketmaster.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import tn.zeros.marketmaster.entity.enums.Role;

import java.util.Collection;
import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Entity
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstName;
    private String lastName;

    @Column(unique = true)
    private String email;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Portfolio portfolio;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Trade> trades;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }


}

```````

`exception\CustomAuthenticationException.java`:

```````java
package tn.zeros.marketmaster.exception;

public class CustomAuthenticationException extends RuntimeException {
    public CustomAuthenticationException(String message) {
        super(message);
    }
}

```````

`exception\TokenValidationException.java`:

```````java
package tn.zeros.marketmaster.exception;

public class TokenValidationException extends RuntimeException {
    public TokenValidationException(String message) {
        super(message);
    }
}
```````

`exception\UserAlreadyExistsException.java`:

```````java
package tn.zeros.marketmaster.exception;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
```````

`repository\UserRepository.java`:

```````java
package tn.zeros.marketmaster.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tn.zeros.marketmaster.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}
```````

`security\JwtAuthenticationFilter.java`:

```````java
package tn.zeros.marketmaster.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tn.zeros.marketmaster.repository.UserRepository;
import tn.zeros.marketmaster.service.JwtTokenService;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```````

`service\AuthenticationService.java`:

```````java
package tn.zeros.marketmaster.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import tn.zeros.marketmaster.dto.LoginRequestDTO;
import tn.zeros.marketmaster.dto.SignupRequestDTO;
import tn.zeros.marketmaster.dto.TokenResponseDTO;
import tn.zeros.marketmaster.entity.User;
import tn.zeros.marketmaster.exception.TokenValidationException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final TokenStorageService tokenStorageService;
    private final UserService userService;
    private final UserDetailsService userDetailsService;

    public TokenResponseDTO authenticate(LoginRequestDTO loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String accessToken = jwtTokenService.generateToken(userDetails);
        String refreshToken = jwtTokenService.generateRefreshToken(userDetails);

        tokenStorageService.storeRefreshToken(userDetails.getUsername(), refreshToken);

        return new TokenResponseDTO(accessToken, refreshToken);
    }

    public TokenResponseDTO refreshToken(String refreshToken) {
        String username = jwtTokenService.extractUsername(refreshToken);
        if (!tokenStorageService.validateRefreshToken(username, refreshToken)) {
            throw new TokenValidationException("Invalid refresh token");
        }

        UserDetails userDetails = loadUserByUsername(username);
        String newAccessToken = jwtTokenService.generateToken(userDetails);

        return new TokenResponseDTO(newAccessToken, refreshToken);
    }

    public void logout(String username) {
        tokenStorageService.removeRefreshToken(username);
        SecurityContextHolder.clearContext();
    }

    public User signup(SignupRequestDTO signupRequest) {
        return userService.signup(signupRequest);
    }

    public String getUsernameFromToken(String token) {
        return jwtTokenService.extractUsername(token.replace("Bearer ", ""));
    }

    public UserDetails loadUserByUsername(String username) {
        return userDetailsService.loadUserByUsername(username);
    }
}
```````

`service\JwtTokenService.java`:

```````java
package tn.zeros.marketmaster.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import tn.zeros.marketmaster.util.RSAKeyProperties;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtTokenService {

    private final RSAKeyProperties rsaKeys;

    @Value("${jwt.access-token.expiration}")
    private long jwtExpiration;
    @Value("${jwt.refresh-token.expiration}")
    private long refreshExpiration;

    public JwtTokenService(RSAKeyProperties rsaKeys) {
        this.rsaKeys = rsaKeys;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(rsaKeys.getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(rsaKeys.getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUsernameFromToken(String token) {
        return extractUsername(token.substring(7));
    }
}
```````

`service\TokenStorageService.java`:

```````java
package tn.zeros.marketmaster.service;

import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;

@Service
public class TokenStorageService {
    private final Map<String, String> refreshTokenStore = new HashMap<>();

    public void storeRefreshToken(String username, String refreshToken) {
        refreshTokenStore.put(username, refreshToken);
    }

    public boolean validateRefreshToken(String username, String refreshToken) {
        String storedToken = refreshTokenStore.get(username);
        return storedToken != null && storedToken.equals(refreshToken);
    }

    public void removeRefreshToken(String username) {
        refreshTokenStore.remove(username);
    }
}
```````

`service\UserDetailsServiceImpl.java`:

```````java
package tn.zeros.marketmaster.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import tn.zeros.marketmaster.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
```````

`service\UserService.java`:

```````java
package tn.zeros.marketmaster.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tn.zeros.marketmaster.dto.SignupRequestDTO;
import tn.zeros.marketmaster.entity.User;
import tn.zeros.marketmaster.entity.enums.Role;
import tn.zeros.marketmaster.exception.UserAlreadyExistsException;
import tn.zeros.marketmaster.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User signup(SignupRequestDTO signupRequest) {
        if (userRepository.findByEmail(signupRequest.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("User with this email already exists");
        }

        User user = User.builder()
                .firstName(signupRequest.getFirstName())
                .lastName(signupRequest.getLastName())
                .email(signupRequest.getEmail())
                .password(passwordEncoder.encode(signupRequest.getPassword()))
                .role(Role.USER)
                .build();

        return userRepository.save(user);
    }
}
```````

`util\KeyGeneratorUtility.java`:

```````java
package tn.zeros.marketmaster.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class KeyGeneratorUtility {
    public static KeyPair generateRsaKey(){
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch(Exception e){
            throw new IllegalStateException();
        }
        return keyPair;
    }
}

```````

`util\RSAKeyProperties.java`:

```````java
package tn.zeros.marketmaster.util;

import lombok.Getter;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
@Getter
public class RSAKeyProperties {
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public RSAKeyProperties() {
        KeyPair pair = KeyGeneratorUtility.generateRsaKey();
        this.publicKey = (RSAPublicKey) pair.getPublic();
        this.privateKey = (RSAPrivateKey) pair.getPrivate();
    }
}
```````

`resources\application.properties`:

```````properties
spring.application.name=MarketMaster
server.port=${SERVER_PORT:8081}

spring.datasource.url=jdbc:mysql://${MYSQL_URL:localhost:3306}/MarketMasterDB?createDatabaseIfNotExist=true
spring.datasource.username=${MYSQL_USERNAME:root}
spring.datasource.password=${MYSQL_PASSWORD:}
spring.jpa.show-sql=true
spring.jpa.hibernate.ddl-auto=update
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQLDialect

logging.level.root=INFO
logging.level.org.springframework.security=DEBUG

jwt.access-token.expiration=${JWT_ACCESS_TOKEN_EXPIRATION:300000}
jwt.refresh-token.expiration=${JWT_REFRESH_TOKEN_EXPIRATION:604800000}

frontend.origin=${FRONTEND_ORIGIN:"http://localhost:4200"}
```````
