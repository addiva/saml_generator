package com.luxottica.models;
public class Claims {

    private String name;
    private String surname;
    private String email;
    private String contry;
    private String companyCode;
    private String userID;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getContry() {
        return contry;
    }

    public void setContry(String contry) {
        this.contry = contry;
    }

    public String getCompanyCode() {
        return companyCode;
    }

    public void setCompanyCode(String companyCode) {
        this.companyCode = companyCode;
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public Claims(String name, String surname, String email, String contry, String companyCode, String userID) {
        this.name = name;
        this.surname = surname;
        this.email = email;
        this.contry = contry;
        this.companyCode = companyCode;
        this.userID = userID;
    }

}
