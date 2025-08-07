package com.hope_health.user_service.service.impl;
import com.hope_health.user_service.config.KeycloakSecurityUtil;
import com.hope_health.user_service.config.WebClientConfig;
import com.hope_health.user_service.dto.request.UserLoginRequest;
import com.hope_health.user_service.dto.request.UserRequestDto;
import com.hope_health.user_service.dto.request.UserUpdateRequest;
import com.hope_health.user_service.dto.response.UserResponseDto;
import com.hope_health.user_service.entity.Otp;
import com.hope_health.user_service.entity.UserEntity;
import com.hope_health.user_service.exception.*;
import com.hope_health.user_service.repo.OtpRepo;
import com.hope_health.user_service.repo.UserRepo;
import com.hope_health.user_service.service.UserService;
import com.hope_health.user_service.util.EmailService;
import com.hope_health.user_service.util.OtpGenerator;
import com.hope_health.user_service.util.StandardResponse;
import jakarta.persistence.EntityNotFoundException;
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
import org.springframework.web.reactive.function.client.WebClientException;

import java.util.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final KeycloakSecurityUtil keycloakUtil;
    private final EmailService emailService;
    private final UserRepo userRepo;
    private final OtpRepo otpRepo;
    private final OtpGenerator otpGenerator;
    private final WebClientConfig webClientConfig;

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
            System.out.println(user);
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
            System.out.println("Actual Otp is " + otpObj.getCode());
            System.out.println("provided Otp is " + otp);

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
                emailService.sendEmailVerifyMail(email, user.getName(), code);

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
    public void updateUser(String userId, UserUpdateRequest request) {
       Optional<UserEntity> userEntity = userRepo.findById(userId);
        System.out.println("user entity "+userEntity);
       if(userEntity.isPresent()){
           UserEntity user = userEntity.get();
           System.out.println("user "+user);
           user.setName(request.getName());

           Keycloak keycloak = null;

           UserRepresentation existingUser = null;
           keycloak = keycloakUtil.getKeycloakInstance();
           try {
               existingUser = keycloak.realm(realm).users().get(userId).toRepresentation();
               System.out.println("k user "+existingUser);

           } catch (WebApplicationException e) {
               throw new InternalServerException("Failed to connect to Keycloak: " + e.getMessage());
           } catch (Exception e) {
               throw new InternalServerException("Unexpected error during user lookup: " + e.getMessage());
           }
          if(existingUser != null){
              System.out.println("Keycloak user updating");
              existingUser.setLastName(request.getName());
              System.out.println(request.getEmail());
              existingUser.setFirstName(request.getName());
              existingUser.setEnabled(true);
              existingUser.setEmailVerified(true);
              System.out.println("to update creds");


              keycloak.realm(realm).users().get(userId).update(existingUser);
              System.out.println("Update completed");

              String userRole = user.getRole();
                if(userRole.equalsIgnoreCase("patient")){
                    try {
                        webClientConfig.webClient()
                                .put()
                                .uri("http://localhost:9092/api/patients/update-patient/{userId}", user.getUserId())
                                .bodyValue(request)
                                .retrieve()
                                .bodyToMono(Void.class)
                                .block();
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to update patient in patient service");
                    }

                }
          }
          else {
              throw new EntityNotFoundException("User could not be found in keycloak");
          }

           userRepo.save(user);
       } else {
           throw new EntryNotFoundException("user not found with id in db " + userId);
       }
    }

    @Override
    public void deleteUser(String userId) {
        Keycloak keycloak = null;

        UserRepresentation existingUser = null;
        keycloak = keycloakUtil.getKeycloakInstance();

        UserEntity user = userRepo.findById(userId).orElseThrow(()-> new RuntimeException("User couldn't found with given id "+ userId));

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

            // check role and according to the role create webclient call
            if(user.getRole().equalsIgnoreCase("patient")){
                try{
                    var response = webClientConfig.webClient()
                            .delete()
                            .uri("http://localhost:9092/api/patients/delete-patient/{userId}", userId)
                            .retrieve()
                            .bodyToMono(Void.class)
                            .block();

                    System.out.println(response);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to delete patient from patient service");
                }
            } else if(user.getRole().equalsIgnoreCase("doctor")){
//                try{
//                    webClientConfig.webClient()
//                            .delete()
//                            .uri("http://localhost:9091/api/doctors/delete-doctor/{userId}", user.getUserId())
//                            .retrieve()
//                            .bodyToMono(Void.class)
//                            .block();
//                } catch (Exception e) {
//                    throw new RuntimeException("Failed to delete doctor from doctor service");
//                }
                System.out.println("Ok");
            }

        }

    }

    @Override
    public Boolean updatePassword(String userId, String password, String role) {

        Optional<UserEntity> user = userRepo.findByUserId(userId);
        if(user.isPresent()){

            Keycloak keycloak = null;
            keycloak = keycloakUtil.getKeycloakInstance();
            UserRepresentation representation;
            try {
                representation = keycloak.realm(realm).users().get(userId).toRepresentation();
            } catch (WebApplicationException e) {
                throw new InternalServerException("Failed to connect to Keycloak: " + e.getMessage());
            } catch (Exception e) {
                throw new InternalServerException("Unexpected error during user lookup: " + e.getMessage());
            }

            List<CredentialRepresentation> creds = new ArrayList<>();
            CredentialRepresentation cred = new CredentialRepresentation();
            cred.setValue(password);
            creds.add(cred);
            representation.setCredentials(creds);
            keycloak.realm(realm).users().get(userId).update(representation);
            return true;

        } else {
            throw new EntityNotFoundException("User couldn't be found with given id " + userId);
        }

    }

    @Override
    public Boolean updateEmail(String userId, String email, String role) {
        Optional<UserEntity> user = userRepo.findByUserId(userId);
        Optional<UserEntity> userExistByNewEmail = userRepo.findByEmail(email);
        if(userExistByNewEmail.isPresent()){
            throw new DuplicateEntryException("User with email " + email + " already exists.");
        }
        if(user.isPresent()){

            UserEntity userEntity = user.get();
            userEntity.setEmail(email);
            //--------------------
            userRepo.save(userEntity);
            Optional<Otp> bySystemUserId = otpRepo.findByUserUserId(userEntity.getUserId());
            Otp newOtpObj = bySystemUserId.get();
            String otp = otpGenerator.generateOtp(4);
            //---------------------

            Keycloak keycloak = null;
            keycloak = keycloakUtil.getKeycloakInstance();
            UserRepresentation representation;
            System.out.println("Representation");
            try {
                representation = keycloak.realm(realm).users().get(userId).toRepresentation();
            } catch (WebApplicationException e) {
                throw new InternalServerException("Failed to connect to Keycloak: " + e.getMessage());
            } catch (Exception e) {
                throw new InternalServerException("Unexpected error during user lookup: " + e.getMessage());
            }

            // after changing email/ should direct to email verify and send an otp to new email.
            // first save to the db and save an otp. then check the otp and email then save to the keycloak
            representation.setEmail(email);
            representation.setUsername(email);

            keycloak.realm(realm).users().get(userId).update(representation);
            System.out.println("before web");
            if(role.equalsIgnoreCase("patient")){
                try {
                    System.out.println("try webclient");
                    webClientConfig.webClient().put().uri("http://localhost:9092/api/patients/update-email/{userId}", userId)
                            .bodyValue(email)
                            .retrieve().bodyToMono(StandardResponse.class).block();

                } catch (WebClientException e){
                    System.out.println("Unable to update doctor profile in pat service");
                } catch (Exception e){
                    System.out.println("Unexpected error during user lookup: " + e.getMessage());
                }

            } else if(role.equalsIgnoreCase("doctor")){
                try {
                    System.out.println("try webclient");
                    webClientConfig.webClient().put().uri("http://localhost:9091/api/doctors/update-email/{userId}", userId)
                            .bodyValue(email)
                            .retrieve().bodyToMono(StandardResponse.class).block();

                } catch (WebClientException e){
                    System.out.println("Unable to update doctor profile in doc service");
                } catch (Exception e){
                    System.out.println("Unexpected error during user lookup: " + e.getMessage());
                }
            }

            return true;

        } else {
            throw new EntityNotFoundException("User couldn't be found with given id " + userId);
        }
    }

    @Override
    public boolean forgotPasswordEmailVerify(String email) {
        Optional<UserEntity> user = userRepo.findByEmail(email);

        if(user.isEmpty()){
            throw new EntityNotFoundException("User couldn't be found with given email " + email);
        }
        UserEntity userEntity = user.get();
        if(!userEntity.getIsEmailVerified()){
            throw new UnauthorizedException("User email is not verified, please verify your email first");
        }
        String otp = otpGenerator.generateOtp(4);
        try {
            emailService.sendEmailVerifyMail(email, userEntity.getName(), otp);

            Otp otpObj = userEntity.getOtp();
            otpObj.setCode(otp);
            otpObj.setAttempts(0);
            otpObj.setCreatedDate(new Date());
            otpRepo.save(otpObj);

            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean verifyResetPassword(String email, String otp) {
        Optional<UserEntity> user = userRepo.findByEmail(email);
        if(user.isEmpty()){
            return false;
        }
        UserEntity userEntity = user.get();
        Otp otpObj = otpRepo.findByUserUserId(userEntity.getUserId())
                .orElseThrow(() -> new EntryNotFoundException("No OTP found for the user"));

        if(otpObj.getCode().equals(otp)){
            return true;
        }
        return false;
    }

    @Override
    public boolean setNewPassword(String email, String newPassword) {
        Optional<UserEntity> user = userRepo.findByEmail(email);
        if(user.isEmpty()){
            throw new EntityNotFoundException("User couldn't be found with given email " + email);
        }
        UserEntity userEntity = user.get();
        Keycloak keycloak = null;
        keycloak = keycloakUtil.getKeycloakInstance();
        UserRepresentation representation;
        try {
            representation = keycloak.realm(realm).users().get(userEntity.getUserId()).toRepresentation();
        } catch (WebApplicationException e) {
            throw new InternalServerException("Failed to connect to Keycloak: " + e.getMessage());
        } catch (Exception e) {
            throw new InternalServerException("Unexpected error during user lookup: " + e.getMessage());
        }

        List<CredentialRepresentation> creds = new ArrayList<>();
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setValue(newPassword);
        creds.add(cred);
        representation.setCredentials(creds);
        keycloak.realm(realm).users().get(userEntity.getUserId()).update(representation);

        return true;
    }

    private UserResponseDto createUser(UserRequestDto requestDto, String role) {

        String userId = "";
        Keycloak keycloak = null;

        UserRepresentation existingUser = null;
        keycloak = keycloakUtil.getKeycloakInstance();

        try {
            existingUser = keycloak.realm(realm).users().search(requestDto.getEmail()).stream()
                    .findFirst().orElse(null);


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

        boolean activeStat = false;
        if(role.equalsIgnoreCase("doctor")){
            activeStat = true;
        }
        UserRepresentation userRep = mapUserRep(requestDto, activeStat);
        Response res = keycloak.realm(realm).users().create(userRep);
        if (res.getStatus() == Response.Status.CREATED.getStatusCode()) {
            RoleRepresentation userRole = keycloak.realm(realm).roles().get(role).toRepresentation();
            userId = res.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Arrays.asList(userRole));
            UserEntity createdSystemUser = UserEntity.builder()
                    .userId(userId)
                    .activeState(activeStat)
                    .email(requestDto.getEmail())
                    .name(requestDto.getName())
                    .isAccountNonExpired(true)
                    .isEmailVerified(activeStat)
                    .isAccountNonLocked(true)
                    .isEnabled(activeStat)
                    .createdDate(new Date())
                    .role(role)
                    .build();
            UserEntity savedUser = userRepo.save(createdSystemUser);
            Otp otp = Otp.builder()
                    .otpId(UUID.randomUUID().toString())
                    .code(otpGenerator.generateOtp(4))
                    .createdDate(new Date())
                    .isVerified(activeStat)
                    .attempts(0)
                    .user(savedUser)
                    .build();
            otpRepo.save(otp);
            try {
                emailService.sendWelcomeMail(requestDto.getEmail(), requestDto.getName());
                emailService.sendEmailVerifyMail(requestDto.getEmail(), requestDto.getName(), otp.getCode());
            } catch (Exception e) {
                System.out.println("Email Sending Failed "+ e.getMessage());
            }

            // if it's a patient, we use inter-service call to patient service to save particular patient
            // if it's a doctor we call doctor service through frontend

            if(role.equalsIgnoreCase("patient")){
                try{

                    System.out.println("inside patient service call by web");
                    requestDto.setUserId(savedUser.getUserId());
                    requestDto.setPassword(null);
                    System.out.println(requestDto);

                    System.out.println("web client");
                    webClientConfig.webClient()
                            .post()
                            .uri("http://localhost:9092/api/patients/register-patient")
                            .bodyValue(requestDto)
                            .retrieve()
                            .bodyToMono(UserRequestDto.class)
                            .block();
                } catch (WebClientException e) {
                    throw new RuntimeException(e);
                }
            }

            return toResponse(createdSystemUser);
        }
        throw new BadRequestException("Something went wrong with creating user. Please try again");
    }

    private UserRepresentation mapUserRep(UserRequestDto user, boolean activeStat) {
        String[] nameParts = user.getName() != null ? user.getName().split("\\s+", 2) : new String[]{""};
        UserRepresentation userRep = new UserRepresentation();
        userRep.setUsername(user.getEmail());
        userRep.setFirstName(nameParts.length > 0 ? nameParts[0] : "");
        userRep.setLastName(nameParts.length > 1 ? nameParts[1] : "");
        userRep.setEmail(user.getEmail());
        userRep.setEnabled(activeStat);
        userRep.setEmailVerified(activeStat);
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
                .name(entity.getName())
                .email(entity.getEmail())
                .userId(entity.getUserId())
                .isEmailVerified(entity.getIsEmailVerified())
                .build();
    }
}
