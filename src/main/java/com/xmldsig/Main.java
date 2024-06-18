package com.xmldsig;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


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

		if (args.length > 0 && "--help".equals(args[0])) {
			printHelp();
			return;
		}


		if (args.length != 2) {
			System.err.println("Invalid parameters");
			System.exit(1);
		}
		String xmlFilePath = null;
		String certFilePath = null;

		for (String arg : args) {
			if (arg.endsWith(".xml")) {
				xmlFilePath = arg;
			} else if (arg.endsWith(".crt") || arg.endsWith(".cer")) {
				certFilePath = arg;
			} else {
				System.err.println("Invalid parameter: " + arg);
				System.exit(1);
			}
		}

		checkParameters(xmlFilePath, certFilePath);

		PrivateKey privateKey = getPrivateKey();


		try {
			Document document = XMLLoader.loadXMLDocument(xmlFilePath);

			X509Certificate cert = CrtLoader.loadCertificate(certFilePath);
			signXMLDocument(document, privateKey, cert);

			normalizeElementValue(document, "SignatureValue");
			normalizeElementValue(document, "X509Certificate");

			String newXmlFilePath = addPrefixToFilePath(xmlFilePath);

			try (FileOutputStream fos = new FileOutputStream(newXmlFilePath)) {
				XMLUtils.outputDOM(document, fos);
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}

		System.out.println("The document has been signed");
	}

	private static void checkParameters(String xmlFilePath, String certFilePath) {
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

	private static PrivateKey getPrivateKey() {
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


	private static String addPrefixToFilePath(String filePath) {
		File file = new File(filePath);
		String fileName = file.getName();
		return "singed_" + fileName;
	}


	public static void printHelp() {
		System.out.println("Usage: java -jar yourfile.jar <xml> <cer>");
		System.out.println("Options:");
		System.out.println("  --help       Show this help message");
		System.out.println("Required arguments:");
		System.out.println("  xml          Path to the XML file");
		System.out.println("  crt          Path to the CRT/CER file");
	}

	private static void normalizeElementValue(Document document, String tagName) {
		Element element = (Element) document.getElementsByTagName(tagName).item(0);
		if (element != null) {
			String content = element.getTextContent().replaceAll("[\\r\\n]+", "");
			element.setTextContent(content);
		}

	}
}


