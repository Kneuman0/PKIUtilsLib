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
import java.util.Calendar;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.zeva.tlGen.dataModel.CertificateBean;

import sun.misc.BASE64Encoder;

public abstract class CertificateUtilities {

	
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

	
	@SuppressWarnings("restriction")
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
	
	
	
	
}
