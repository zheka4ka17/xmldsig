package com.xmldsig;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CrtLoader {
	public static X509Certificate loadCertificate(String certFilePath)  {
		FileInputStream certInputStream = null;
		try {
			certInputStream = new FileInputStream(certFilePath);

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return (X509Certificate) certFactory.generateCertificate(certInputStream);
		} catch (FileNotFoundException e) {
			System.err.println("Failed FileNotFoundException ");
			System.exit(1);
		} catch (CertificateException e) {
			System.err.println("Couldn't load  crt document");
			System.exit(1);
		}

		return null;


	}
}


