package com.hope_health.user_service.util;

import com.hope_health.user_service.exception.InternalServerException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.time.Year;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender javaMailSender;
    private final JavaMailSenderImpl mailSender;
    private final EmailTemplateHelper emailTemplateHelper;

    @Value("${spring.mail.properties.mail.smtp.from}")
    private String from;

    public void sendWelcomeMail(String toMail, String name){
        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        simpleMailMessage.setFrom(from);
        simpleMailMessage.setTo(toMail);
        simpleMailMessage.setSubject("Welcome to HopeHealth Service");
        simpleMailMessage.setText("Hello "+name+", \n Thanks For Registering With Us...");
        mailSender.send(simpleMailMessage);
    }

    public void sendEmailVerifyMail(String toMail, String name, String otp){
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(from);
            helper.setTo(toMail);
            helper.setSubject("Verify your email address");

            // Load your HTML template as a String (example shown inline)
            String htmlContent = emailTemplateHelper.loadHtmlTemplate("templates/hope-health-send-login-verification-email-template.html") + name + ",</h1><p>Please verify your email address.</p></body></html>";
            htmlContent = htmlContent.replace("${otp}", otp);
            htmlContent = htmlContent.replace("${year}", String.valueOf(Year.now().getValue()));
            helper.setText(htmlContent, true);

            javaMailSender.send(message);
        } catch (Exception e) {
            throw new InternalServerException("Email send failed");
        }
    }

    public void sendPasswordResetMail(String toMail, String name, String otp){
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(from);
            helper.setTo(toMail);
            helper.setSubject("Verify to reset your password");

            // Load your HTML template as a String (example shown inline)
            String htmlContent = emailTemplateHelper.loadHtmlTemplate("template/hope-health-send-reset-password-verification-email-template.html") + name + ",</h1><p>Please verify your email address.</p></body></html>";
            htmlContent = htmlContent.replace("${otp}", otp);
            htmlContent = htmlContent.replace("${year}", String.valueOf(Year.now().getValue()));
            helper.setText(htmlContent, true);

            javaMailSender.send(message);
        } catch (Exception e) {
            throw new InternalServerException("Email send failed");
        }
    }

}
