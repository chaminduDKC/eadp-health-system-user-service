package com.hope_health.user_service.service.impl;
import com.hope_health.user_service.config.KeycloakSecurityUtil;
import com.hope_health.user_service.dto.request.UserLoginRequest;
import com.hope_health.user_service.dto.request.UserRequestDto;
import com.hope_health.user_service.dto.response.UserResponseDto;
import com.hope_health.user_service.entity.Otp;
import com.hope_health.user_service.entity.UserEntity;
import com.hope_health.user_service.exception.*;
import com.hope_health.user_service.repo.OtpRepo;
import com.hope_health.user_service.repo.UserRepo;
import com.hope_health.user_service.service.UserService;
import com.hope_health.user_service.util.EmailService;
import com.hope_health.user_service.util.OtpGenerator;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final KeycloakSecurityUtil keycloakUtil;
    private final EmailService emailService;
    private final UserRepo userRepo;
    private final OtpRepo otpRepo;
    private final OtpGenerator otpGenerator;

    @Value("${keycloak.config.realm}")
    private String realm;

    @Value("${keycloak.config.client-id}")
    private String clientId;


    @Value("${keycloak.config.secret}")
    private String secret;

    @Value("${spring.security.oauth2.resourceserver.jwt.token-uri}")
    private String keyCloakApiUrl;

    @Override
    public UserResponseDto createPatient(UserRequestDto request) {
        return createUser(request, "patient");
    }

    @Override
    public UserResponseDto createDoctor(UserRequestDto request) {
        return createUser(request, "doctor");
    }

    @Override
    public Object login(UserLoginRequest request) {
        try {
            Optional<UserEntity> selectedUser = userRepo.findByEmail(request.getUsername());
            UserEntity user = selectedUser.get();
            if(!user.getIsEmailVerified()){

                Otp selectedUserOtp = user.getOtp();

                String otp = otpGenerator.generateOtp(4);
                emailService.sendEmailVerifyMail(request.getUsername(), request.getUsername(), otp);
                selectedUserOtp.setCode(otp);
                selectedUserOtp.setCreatedDate(new Date());
                otpRepo.save(selectedUserOtp);
                throw new RedirectionException("Your email has not been verified. Please verify your email");

            } else{
                MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
                requestBody.add("client_id", clientId);
                requestBody.add("grant_type", OAuth2Constants.PASSWORD);
                requestBody.add("username", request.getUsername());
                requestBody.add("client_secret", secret);
                requestBody.add("password", request.getPassword());

                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                RestTemplate restTemplate = new RestTemplate();
                ResponseEntity<Object> response = restTemplate.postForEntity(keyCloakApiUrl, requestBody, Object.class);
                return response.getBody();
            }

        } catch (Exception e){
            System.out.println(e);
            if (e instanceof RedirectionException) {
                throw new RedirectionException("Your email has not been verified. Please verify your email "+e.toString());
            } else {
                throw new UnauthorizedException("Invalid username or password. Please double-check your credentials and try again."+e.toString());
            }

        }
    }

    @Override
    public boolean verifyUser(String email, String otp) {
        try {
            Optional<UserEntity> selectedUser = userRepo.findByEmail(email);
            if(selectedUser.isEmpty()){
                throw new EntryNotFoundException("No user found with provided email");
            }
            UserEntity user = selectedUser.get();
            Otp otpObj = otpRepo.findByUserUserId(user.getUserId()).get();

            if(otpObj.getIsVerified()){
                throw new BadRequestException("This otp has been used before, request for another otp and try again");
            }

            if(otpObj.getAttempts()>= 5){
                String code = otpGenerator.generateOtp(4);
                emailService.sendEmailVerifyMail(email, "", code);

                otpObj.setAttempts(0);
                otpObj.setCode(code);
                otpObj.setCreatedDate(new Date());
                otpRepo.save(otpObj);
                throw new TooManyRequestException("many unsucceful attempts, new otp sent and verify ");
            }

            if(otpObj.getCode().equals(otp)){

                UserRepresentation keycloakUser = keycloakUtil.getKeycloakInstance().realm(realm)
                        .users()
                        .search(email)
                        .stream()
                        .findFirst()
                        .orElseThrow(() -> new EntryNotFoundException("User not found! Contact support for assistance"));

                keycloakUser.setEmailVerified(true);
                keycloakUser.setEnabled(true);

                keycloakUtil.getKeycloakInstance().realm(realm)
                        .users()
                        .get(keycloakUser.getId())
                        .update(keycloakUser);

                user.setActiveState(true);
                user.setIsEnabled(true);
                user.setIsEmailVerified(true);

                userRepo.save(user);

                otpObj.setIsVerified(true);
                otpObj.setAttempts(otpObj.getAttempts() + 1);

                otpRepo.save(otpObj);

                return true;

            } else {
                otpObj.setAttempts(otpObj.getAttempts() + 1);
                otpRepo.save(otpObj);
            }



        } catch (Exception e){
           throw new InternalServerException("Something went wrong, try again");
        }
        return false;
    }

    @Override
    public boolean resendOtp(String email) {
        try{
            Optional<UserEntity> selectedUser = userRepo.findByEmail(email);
            if(selectedUser.isEmpty()){
                throw new DuplicateEntryException("No user available with this user");
            }
            UserEntity user = selectedUser.get();
            if(user.getIsEmailVerified()){
                throw new DuplicateEntryException("This email is verified already");
            }
            Otp otp = user.getOtp();
            if(otp.getAttempts()>= 5){
                String code = otpGenerator.generateOtp(4);
                emailService.sendEmailVerifyMail(email, user.getFirstName(), code);

                otp.setCreatedDate(new Date());
                otp.setCode(code);
                otp.setAttempts(0);
                otpRepo.save(otp);
            }
            return true;
        } catch (Exception e){
            if (e instanceof DuplicateEntryException) {
                throw new DuplicateEntryException("The email is already activated");
            } else if (e instanceof TooManyRequestException) {
                throw new TooManyRequestException("Too many unsuccessful attempts. New OTP sent and please verify.");
            } else if (e instanceof EntryNotFoundException) {
                throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");
            } else {
                throw new UnauthorizedException("Invalid username or password. Please double-check your credentials and try again.");
            }
        }
    }

    @Override
    public Object getUserById(String userId) {
        try {
            Optional<UserEntity> selectedUser = userRepo.findByUserId(userId);
            if(selectedUser.isEmpty()){
                throw new EntryNotFoundException("User not found with the id");
            }
            UserEntity user = selectedUser.get();
            return toResponse(user);

        } catch (Exception e){
            System.out.println("user couldn't found with this id "+e.getMessage());
            return null;
        }
    }

    @Override
    public boolean updateUser(String userId) {
        return false;
    }

    @Override
    public Boolean deleteUser(String userId) {
        Keycloak keycloak = null;

        UserRepresentation existingUser = null;
        keycloak = keycloakUtil.getKeycloakInstance();

        UserEntity user = userRepo.findById(userId).orElseThrow(()-> new RuntimeException("User couldn't found with given id"));

        String userEmail = user.getEmail();

        try{
            existingUser = keycloak.realm(realm).users().search(userEmail).stream().findFirst().orElse(null);
        }catch (WebApplicationException e) {
            throw new InternalServerException("Failed to connect to Keycloak: " + e.getMessage());
        } catch (Exception e) {
            throw new InternalServerException("Unexpected error during user lookup: " + e.getMessage());
        }
        if(existingUser != null){
            keycloak.realm(realm).users().delete(existingUser.getId());

            Optional<UserEntity> userEntity = userRepo.findByEmail(userEmail);
            Optional<Otp> userOtp = otpRepo.findByUserUserId(userId);

            userRepo.deleteById(userId);
            String otpId = userOtp.get().getOtpId();
            otpRepo.deleteById(otpId);
            return true;
        }

        return false;
    }

    private UserResponseDto createUser(UserRequestDto requestDto, String role) {

        String userId = "";
        Keycloak keycloak = null;

        UserRepresentation existingUser = null;
        keycloak = keycloakUtil.getKeycloakInstance();

        try {
            existingUser = keycloak.realm(realm).users().search(requestDto.getEmail()).stream()
                    .findFirst().orElse(null);
            System.out.println(existingUser);

        } catch (WebApplicationException e) {
            throw new InternalServerException("Failed to connect to Keycloak: " + e.getMessage());
        } catch (Exception e) {
            throw new InternalServerException("Unexpected error during user lookup: " + e.getMessage());
        }

        if (existingUser != null) {
            System.out.println("start");
            Optional<UserEntity> byEmail = userRepo.findByEmail(existingUser.getEmail());
            System.out.println("end");
            System.out.println(byEmail.isEmpty());
            if (byEmail.isEmpty()) {
                keycloak.realm(realm).users().delete(existingUser.getId());

            } else {
                throw new DuplicateEntryException("User with email " + requestDto.getEmail() + " already exists.");
            }

        } else {

            Optional<UserEntity> byEmail = userRepo.findByEmail(requestDto.getEmail());

            if (byEmail.isPresent()) {
                Optional<Otp> bySystemUserId = otpRepo.findByUserUserId(byEmail.get().getUserId());
                if (bySystemUserId.isPresent()) {
                    otpRepo.deleteById(bySystemUserId.get().getOtpId());
                }
                userRepo.deleteById(byEmail.get().getUserId());
            }
        }

        UserRepresentation userRep = mapUserRep(requestDto);
        Response res = keycloak.realm(realm).users().create(userRep);
        if (res.getStatus() == Response.Status.CREATED.getStatusCode()) {
            RoleRepresentation userRole = keycloak.realm(realm).roles().get(role).toRepresentation();
            userId = res.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Arrays.asList(userRole));
            UserEntity createdSystemUser = UserEntity.builder()
                    .userId(userId)
                    .activeState(false)
                    .email(requestDto.getEmail())
                    .firstName(requestDto.getFirstName())
                    .lastName(requestDto.getLastName())
                    .isAccountNonExpired(true)
                    .isEmailVerified(false)
                    .isAccountNonLocked(true)
                    .isEnabled(false)
                    .createdDate(new Date())
                    .build();
            UserEntity savedUser = userRepo.save(createdSystemUser);
            Otp otp = Otp.builder()
                    .otpId(UUID.randomUUID().toString())
                    .code(otpGenerator.generateOtp(4))
                    .createdDate(new Date())
                    .isVerified(false)
                    .attempts(0)
                    .user(savedUser)
                    .build();
            otpRepo.save(otp);
            emailService.sendWelcomeMail(requestDto.getEmail(), requestDto.getFirstName());
            emailService.sendEmailVerifyMail(requestDto.getEmail(), requestDto.getFirstName(), otp.getCode());
            return toResponse(createdSystemUser);
        }
        throw new BadRequestException("Something went wrong with creating user. Please try again");
    }

    private UserRepresentation mapUserRep(UserRequestDto user) {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setUsername(user.getEmail());
        userRep.setFirstName(user.getFirstName());
        userRep.setLastName(user.getLastName());
        userRep.setEmail(user.getEmail());
        userRep.setEnabled(false);
        userRep.setEmailVerified(false);
        List<CredentialRepresentation> creds = new ArrayList<>();
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setTemporary(false);
        cred.setValue(user.getPassword());
        creds.add(cred);
        userRep.setCredentials(creds);
        return userRep;
    }

    private UserResponseDto toResponse(UserEntity entity){
        return UserResponseDto.builder()
                .FirstName(entity.getFirstName())
                .lastName(entity.getLastName())
                .email(entity.getEmail())
                .userId(entity.getUserId())
                .isEmailVerified(entity.getIsEmailVerified())
                .build();
    }
}
