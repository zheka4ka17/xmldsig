package com.xmldsig;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CrtLoader {
	public static X509Certificate loadCertificate(String certFilePath) throws Exception {
		   FileInputStream certInputStream = new FileInputStream(certFilePath);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return (X509Certificate) certFactory.generateCertificate(certInputStream);
	}
}


