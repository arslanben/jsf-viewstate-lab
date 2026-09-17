package com.auroratelecom.portal;

import java.io.Serializable;
import java.security.SecureRandom;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;

public class LoginBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final String CAPTCHA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private String username;
    private String password;
    private String captcha;
    private String captchaInput;

    public LoginBean() {
        newCaptcha();
    }

    public String login() {
        FacesContext context = FacesContext.getCurrentInstance();

        if (captchaInput == null || !captcha.equals(captchaInput.trim().toUpperCase())) {
            context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,
                    "The security code is not correct.", null));
            newCaptcha();
            return null;
        }

        if (!"dealer01".equals(username) || !"dealer01".equals(password)) {
            context.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,
                    "Invalid username or password.", null));
            newCaptcha();
            return null;
        }

        return "dashboard";
    }

    private void newCaptcha() {
        StringBuilder value = new StringBuilder(4);
        for (int i = 0; i < 4; i++) {
            value.append(CAPTCHA_ALPHABET.charAt(RANDOM.nextInt(CAPTCHA_ALPHABET.length())));
        }
        captcha = value.toString();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getCaptcha() {
        return captcha;
    }

    public String getCaptchaInput() {
        return captchaInput;
    }

    public void setCaptchaInput(String captchaInput) {
        this.captchaInput = captchaInput;
    }
}
