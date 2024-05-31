package com.xmldsig;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import static com.xmldsig.XMLSigner.signXMLDocument;

public class Main {

	public static void main(String[] args) throws NoSuchAlgorithmException {

		if (args.length != 2) {
			System.err.println("Invalid parameters");
			System.exit(1);
		}
		String xmlFilePath = null;
		String certFilePath = null;

		for (String arg : args) {
			if (arg.endsWith(".xml")) {
				xmlFilePath = arg;
			} else if (arg.endsWith(".crt")) {
				certFilePath = arg;
			} else {
				System.err.println("Invalid parameter: " + arg);
				System.exit(1);
			}
		}

		checkParameters(xmlFilePath, certFilePath);
        //Вопрос мы получаем сертификат или keyStore файл
		PrivateKey privateKey = getPrivateKey();



		try {
			Document document = XMLLoader.loadXMLDocument(xmlFilePath);
			X509Certificate cert = CrtLoader.loadCertificate(certFilePath);
			signXMLDocument(document, privateKey, cert);

			try (FileOutputStream fos = new FileOutputStream("signed_document.xml")) {
				XMLUtils.outputDOM(document, fos);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}

		System.out.println("Signed document");
	}

	private static void checkParameters(String xmlFilePath, String certFilePath){
		if (xmlFilePath == null || certFilePath == null) {
			System.err.println("Missing required parameters");
			System.exit(1);
		}
		if (!Files.exists(new File(xmlFilePath).toPath())) {
			System.err.println("XML file does not exist: " + xmlFilePath);
			System.exit(1);
		}
		if (!Files.exists(new File(certFilePath).toPath())) {
			System.err.println("Certificate does not exist: " + certFilePath);
			System.exit(1);
		}
	}

	private static PrivateKey getPrivateKey(){
		KeyGenerator keyGenerator = new KeyGenerator();
		KeyPair keyPair = null;
		try {
			keyPair = keyGenerator.createKeyPair();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Keypair generate Error");
			System.exit(0);
		}
		return keyPair.getPrivate();

	}


	}


