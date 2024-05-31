package com.xmldsig;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;


public class XMLLoader {
	public static Document loadXMLDocument(String filePath) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		return dbf.newDocumentBuilder().parse(filePath);

	}


}
