package com.dev.userservice.services;

import com.dev.userservice.dtos.UserDto;
import com.dev.userservice.models.Session;
import com.dev.userservice.models.SessionStatus;
import com.dev.userservice.models.User;
import com.dev.userservice.repositories.SessionRepository;
import com.dev.userservice.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.util.MultiValueMapAdapter;

import javax.crypto.SecretKey;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {
    private UserRepository userRepository;
    private SessionRepository sessionRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private SecretKey secretKey;

    @Autowired
    public AuthService(UserRepository userRepository, SessionRepository sessionRepository,BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.secretKey = Jwts.SIG.HS256.key().build();
    }

    // Note: This method should return a custom object containing token, headers, etc
    // For now, to avoid creating an object, directly returning ResponseEntity from here
    public ResponseEntity<UserDto> login(String email, String password) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            return null;
        }

        User user = userOptional.get();
        if(!bCryptPasswordEncoder.matches(password, user.getPassword()))
        {
            throw new RuntimeException("Password/Username does not match");
        }



        //String token = RandomStringUtils.randomAlphanumeric(30);
        Map<String,Object> jwtData = new HashMap<>();
        jwtData.put("email",email);
        jwtData.put("createdAt", new Date());
        jwtData.put("expiryAt", Date.from(LocalDate.now().plusDays(3).atStartOfDay(ZoneId.systemDefault()).toInstant()));

        String token = Jwts.builder()
                .claims(jwtData)
                .signWith(secretKey)
                .compact();




        Session session = new Session();
        session.setSessionStatus(SessionStatus.ACTIVE);
        session.setToken(token);
        session.setUser(user);

        sessionRepository.save(session);

        UserDto userDto = UserDto.from(user);

        MultiValueMap<String, String> headers = new MultiValueMapAdapter<>(new HashMap<>());
        headers.add(HttpHeaders.SET_COOKIE, "auth-token:" + token);

        return new ResponseEntity<UserDto>(userDto, headers, HttpStatus.OK);
    }

    public void logout(String token, Long userId) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token, userId);
        if (sessionOptional.isEmpty()) {
            return;
        }

        Session session = sessionOptional.get();

        session.setSessionStatus(SessionStatus.ENDED);

        sessionRepository.save(session);
    }

    public UserDto signUp(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password));

        User savedUser = userRepository.save(user);

        return UserDto.from(savedUser);
    }

    public SessionStatus validate(String token, Long userId) {
        Optional<Session> sessionOptional = sessionRepository.findByTokenAndUser_Id(token, userId);

        if (sessionOptional.isEmpty()) {
            return SessionStatus.ENDED;
        }

        Session session = sessionOptional.get();

        if (!session.getSessionStatus().equals(SessionStatus.ACTIVE)) {
            return SessionStatus.ENDED;
        }


        //Write logic for verification here
        Jws<Claims> claimsJws = Jwts
                .parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token);

        String email = (String) claimsJws.getPayload().get("email");
        Date expiryAt = (Date) claimsJws.getPayload().get("expiryAt");

//        if(new Date()>expiryAt)
//        {
//            session end;
//        }



        return SessionStatus.ACTIVE;
    }

}
