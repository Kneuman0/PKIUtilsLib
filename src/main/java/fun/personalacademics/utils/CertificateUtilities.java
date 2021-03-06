package fun.personalacademics.utils;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import biz.ui.filesystem.FriendlyExtensionFilter;
import fun.personalacademics.model.CertificateBean;
import javafx.stage.FileChooser.ExtensionFilter;
import sun.misc.BASE64Encoder;

@SuppressWarnings("restriction")
public abstract class CertificateUtilities{
	
	
	public static List<ExtensionFilter> BUNDLE_EXTS = 
			new FriendlyExtensionFilter("Bundles", "*.p7b", "*.p7c").get();
	
	public static List<ExtensionFilter> PEM_EXTS = 
			new FriendlyExtensionFilter("PEM Files", "*.pem").get();
	
	public static List<ExtensionFilter> X509_CERT_EXTS = 
			new FriendlyExtensionFilter("X509 Certs", "*.cer", "*.der").get();
	
	public static List<ExtensionFilter> ALL_CERT_EXTS = 
			new FriendlyExtensionFilter("Cert Files", "*.p7b", "*.p7c", "*.pem",
			"*.der", "*.p12", "*.pfx", "*.cer", "*.crt").get();

	
	public static String generateX509SKI(X509Certificate cert) {
		JcaX509ExtensionUtils util = null;
		try {
			util = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] array = util.createSubjectKeyIdentifier(cert.getPublicKey()).getKeyIdentifier();
		
		return DatatypeConverter.printHexBinary(array);
	}
	
	public static String generatePublicKeyString(X509Certificate cert){
		JcaX509ExtensionUtils util = null;
		try {
			util = new JcaX509ExtensionUtils();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return RadixConverter.binaryTextToHex(
				util.createSubjectKeyIdentifier(cert.getPublicKey()).getKeyIdentifier());
	}


	public static String insertPeriodically(String text, String insert,
			int period) {
		StringBuilder builder = new StringBuilder(text.length()
				+ insert.length() * (text.length() / period) + 1);

		int index = 0;
		String prefix = "";
		while (index < text.length()) {
			// Don't put the insert in the very first iteration.
			// This is easier than appending it *after* each substring
			builder.append(prefix);
			prefix = insert;
			builder.append(text.substring(index,
					Math.min(index + period, text.length())));
			index += period;
		}
		return builder.toString();
	}
	
	public static String toBase64Neat(String base64){
		return insertPeriodically(base64, "\n", 64);
	}
	
	public static String toPemFormat(String base64){
		if(base64.contains("-----")){
			String matchHeader = "-----.*";
			Pattern pattern = Pattern.compile(matchHeader);
			Matcher matcher = pattern.matcher(base64);
			
			String fixedB64 = "";
			while(matcher.find()){
				int indexStartBase64 = matcher.end();
				int indexEndBase64 = 0;
				if(matcher.find()){
					indexEndBase64 = matcher.start();
				}else{
					continue;
				}
				
				fixedB64 += "\n-----BEGIN CERTIFICATE-----\n"
						+ fixBase64(base64.substring(indexStartBase64, indexEndBase64))
						+ "\n-----END CERTIFICATE-----";
			}
			
			return fixedB64;
		}else{
			return "\n-----BEGIN CERTIFICATE-----\n"
					+ fixBase64(base64)
					+ "\n-----END CERTIFICATE-----\n";
		}
				
	}

	
	public static String toPemFormat(X509Certificate cert) throws CertificateEncodingException{
		BASE64Encoder encoder = new BASE64Encoder();
		return toPemFormat(encoder.encode(cert.getEncoded()));
	
	}
	
	public static String toPemFormat(CertificateBean certBean){
		return toPemFormat(certBean.getBase64Parent());

	}
		
	public static String fixBase64(String b64){
		return CertificateUtilities.toBase64Neat(b64.replaceAll("[^A-Za-z0-9+/=]", ""));
	}
	
	public static X509Certificate createCertificate(String dn, String issuer,
	        PublicKey publicKey, PrivateKey privateKey) throws Exception {
		X500Name iss = new X500Name(issuer);
		X500Name DN = new X500Name(dn);
		ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
		SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		Calendar cal = Calendar.getInstance();
		cal.setTime(new Date());
		cal.add(Calendar.DATE, 15);
	    X509v3CertificateBuilder certGenerator = new X509v3CertificateBuilder(
	    		iss, new BigInteger("1"), new Date(), cal.getTime(), DN, info);
	    
	    CertificateFactory fact = CertificateFactory.getInstance("X.509");
	    ByteArrayInputStream in = new ByteArrayInputStream(certGenerator.build(sigGen).getEncoded());
	    return (X509Certificate)fact.generateCertificate(in);
	}
	
	public static X509Certificate getCertWithoutLineBreaks(X509Certificate cert){
		X509Certificate newCert = null;
		try {
			BASE64Encoder encoder = new BASE64Encoder();
			String base64 = encoder.encode(cert.getEncoded()).replaceAll("[ \n\t\r]", "");
			String begin = "-----BEGIN CERTIFICATE-----\n";
			String end = "\n-----END CERTIFICATE-----";
			String total = begin + base64 + end;
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			ByteArrayInputStream input = new ByteArrayInputStream(total.getBytes());
			newCert = (X509Certificate)factory.generateCertificate(input);
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return newCert;
	}
	
	public static String generateCertThumbprint(X509Certificate cert) throws CertificateEncodingException{
		return DigestUtils.sha1Hex(cert.getEncoded());
	}
	
	public static String toColonSepHex(String hex){
		return insertPeriodically(hex.replaceAll("[^0-9a-zA-z ]", "").replace(" ", ":").toUpperCase(), "\n", 66);
	}
	
	public static String getHexASN1SubjectPubKeyInfo(X509Certificate cert){
		SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfo.getInstance(cert.getPublicKey().getEncoded());
		return RadixConverter.binaryTextToHex(pubKeyInfo.getPublicKeyData().getBytes());
	}
	
	public static String printExtension(X509Certificate cert, String extension){
		return "Extension: " + extension + "\nDescription: "
				+ getExtensionDesc(extension) + "\nValue: " +
				RadixConverter.binaryTextToHex(cert.getExtensionValue(extension));
	}
	
	public static Map<String, String> getExtensionDescriptions(){
		Map<String, String> extensions = new HashMap<>();
		extensions.put(Extension.auditIdentity.getId(), "Audit Identity");
		extensions.put(Extension.authorityInfoAccess.getId(), "Authority Info Access");
		extensions.put(Extension.authorityKeyIdentifier.getId(), "Authority Key Identifier");
		extensions.put(Extension.basicConstraints.getId(), "Basic Constraints");
		extensions.put(Extension.biometricInfo.getId(), "Biometric Info");
		extensions.put(Extension.certificateIssuer.getId(), "Certificate Issuer");
		extensions.put(Extension.certificatePolicies.getId(), "Certificate Policies");
		extensions.put(Extension.cRLDistributionPoints.getId(), "CRL Distribution Points");
		extensions.put(Extension.cRLNumber.getId(), "CRL Number");
		extensions.put(Extension.deltaCRLIndicator.getId(), "Delta CRL Indicator");
		extensions.put(Extension.extendedKeyUsage.getId(), "Extended Key Usage");
		extensions.put(Extension.freshestCRL.getId(), "Freshest CRL");
		extensions.put(Extension.inhibitAnyPolicy.getId(), "Inhibit Any Policy");
		extensions.put(Extension.instructionCode.getId(), "Instruction Code");
		extensions.put(Extension.invalidityDate.getId(), "Invalidity Date");
		extensions.put(Extension.issuerAlternativeName.getId(), "Issuer Alternative Name");
		extensions.put(Extension.issuingDistributionPoint.getId(), "Issuing Distribution Point");
		extensions.put(Extension.keyUsage.getId(), "Key Usage");
		extensions.put(Extension.logoType.getId(), "Logo Type");
		extensions.put(Extension.nameConstraints.getId(), "Name Constraints");
		extensions.put(Extension.noRevAvail.getId(), "No Rev Avail");
		extensions.put(Extension.policyConstraints.getId(), "Policy Constraints");
		extensions.put(Extension.policyMappings.getId(), "Policy Mappings");
		extensions.put(Extension.privateKeyUsagePeriod.getId(), "Private Key Usage Period");
		extensions.put(Extension.qCStatements.getId(), "QC Statements");
		extensions.put(Extension.reasonCode.getId(), "Reason Code");
		extensions.put(Extension.reasonCode.getId(), "Reason Code");
		extensions.put(Extension.subjectAlternativeName.getId(), "Subject Alternative Name");
		extensions.put(Extension.subjectDirectoryAttributes.getId(), "Subject Directory Attributes");
		extensions.put(Extension.subjectInfoAccess.getId(), "Subject Info Access");
		extensions.put(Extension.subjectKeyIdentifier.getId(), "Subject Key Identifier");
		extensions.put(Extension.targetInformation.getId(), "Target Information");
		
		return extensions;
	}
	
	public static String getExtensionDesc(String oid){
		try {
			return getExtensionDescriptions().get(oid);
		} catch (Exception e) {
			return "Unknow Extension: + oid";
		}
	}
	
	public static List<X509Certificate> asX509Certificates(List<CertificateBean> beans){
		List<X509Certificate> certs = new ArrayList<>();
		for(CertificateBean bean : beans){
			certs.add(bean.getParentCert());
		}
		
		return certs;
	}
	
	
}
