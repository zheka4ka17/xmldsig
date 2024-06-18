package com.xmldsig;

import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;


public class XMLLoader {
	public static Document loadXMLDocument(String filePath) {
		DocumentBuilderFactory dbf;
		try {
			dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			return dbf.newDocumentBuilder().parse(filePath);

		} catch (IOException e) {
			System.err.println("Failed IOException");
			System.exit(1);
		} catch (Exception e) {
			System.err.println("Couldn't parse xml document");
			System.exit(1);
		}
		return null;
	}

	}
