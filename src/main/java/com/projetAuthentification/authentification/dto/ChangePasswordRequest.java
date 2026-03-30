package com.projetAuthentification.authentification.dto;

/**
 * DTO pour la requête de changement de mot de passe.
 * Reçoit le JSON :
 * {
 *   "email": "toto@example.com",
 *   "oldPassword": "pwd1234",
 *   "newPassword": "NewPassword123!",
 *   "confirmPassword": "NewPassword123!"
 * }
 */
public class ChangePasswordRequest {

    private String email;
    private String oldPassword;
    private String newPassword;
    private String confirmPassword;

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getOldPassword() { return oldPassword; }
    public void setOldPassword(String oldPassword) { this.oldPassword = oldPassword; }

    public String getNewPassword() { return newPassword; }
    public void setNewPassword(String newPassword) { this.newPassword = newPassword; }

    public String getConfirmPassword() { return confirmPassword; }
    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}