package com.luxottica;

import com.luxottica.models.Claims;
import com.luxottica.utils.MetadataUtils;
import com.luxottica.utils.SamlUtils;

import java.util.Base64;

public class Main {
    public static void main(String[] args) {
        try {
            String meta = MetadataUtils.generator();
            System.out.println("Metadata:");
            System.out.println(meta);
            String saml = SamlUtils.generate(new Claims("nome","cognome","email@dominio.al","IT",null,"id"));
            System.out.println();
            System.out.println("Saml:");
            System.out.println(saml);
            System.out.println();
            System.out.println("Saml64:");
            System.out.println(Base64.getEncoder().encodeToString(saml.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}