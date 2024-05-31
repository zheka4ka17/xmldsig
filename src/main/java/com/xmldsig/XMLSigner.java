package com.xmldsig;


import org.apache.xml.security.Init;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;


import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

public class XMLSigner {

	static {
		Init.init();
	}

	public static void signXMLDocument(Document document, PrivateKey privateKey, X509Certificate certificate) throws Exception {
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

		DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA1, null);
		CanonicalizationMethod cm = factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
		SignatureMethod sm = factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);

		Transform envTransform = factory.newTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE, (TransformParameterSpec) null);
		Transform exc14nTransform = factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null);
		List<Transform> transformList = List.of(envTransform, exc14nTransform);

		Reference reference = factory.newReference("", digestMethod, transformList, null, null);
		SignedInfo signedInfo = factory.newSignedInfo(cm, sm, Collections.singletonList(reference));

		KeyInfoFactory keyInfoFactory = factory.getKeyInfoFactory();
		X509Data x509Data = (X509Data) keyInfoFactory.newX509Data(Collections.singletonList(certificate));
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));

		DOMSignContext dsc = new DOMSignContext(privateKey, document.getDocumentElement());
		XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);

		signature.sign(dsc);
	}
}