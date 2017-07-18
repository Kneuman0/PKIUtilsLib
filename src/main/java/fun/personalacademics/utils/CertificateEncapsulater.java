package fun.personalacademics.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.crypto.dsig.XMLSignatureException;

import java.security.cert.X509Certificate;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.exceptions.XMLSecurityException;

import com.zeva.tlGen.dataModel.CertificateBean;
import com.zeva.trustlist.popup.PasswordPopup;

import fun.personalacademics.model.FileSystemKeyStoreKeyingDataProviderFactory;
import javafx.scene.control.ButtonType;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;

public class CertificateEncapsulater {
	
	public static enum CERT_TYPES {CER, PEM, P7B, P7C, PFX, P12};
	List<X509Certificate> certs;
	
	/**
	 * Uses the file extension to determine the file type. Reads in the entire file and 
	 * stores it as X509Certificates
	 * @param certFile
	 * @throws Exception 
	 */
	public CertificateEncapsulater(File certFile) throws Exception {
		certs = new ArrayList<>();
		if(certFile.getAbsolutePath().toLowerCase().endsWith("cer")){
			loadCERFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith("pem")){
			loadPEMFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith("p7b") ||
				certFile.getAbsolutePath().toLowerCase().endsWith("p7c")){
			loadP7BFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith("pfx")){
			loadPFXFile(certFile);
		}else if(certFile.getAbsolutePath().toLowerCase().endsWith(".p12")){
			loadPFXFile(certFile);
		}else{
			throw new Exception(certFile.getAbsolutePath() + "is not a supported file type");
		}
		
		
	}
	
	
	/**
	 * Reads in the certificate file and encapsulates the certificates using the method type specified.
	 * @param base64 base 64 string containing certificate information. Each certificate must be
	 * 		bounded at the beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by -----END CERTIFICATE-----.
	 * @param type type of certificate file being passed in
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 * @throws CMSException
	 */
	public CertificateEncapsulater(String base64, CERT_TYPES type) throws Exception{
		certs = new ArrayList<>();
		if(type == CERT_TYPES.CER){
			loadCERFile(base64);
		}else if(type == CERT_TYPES.PEM){
			loadPEMFile(base64);
		}else {
			loadP7BFile(base64);
		}
	}
	
	/**
	 * Accepts a certificate file containing one or more certificates. Must specify the encoding type of the file. This
	 * constructor is useful if the certificate file is encoded differently then what the extension indicates
	 * @param certFile file containing one or more certificates
	 * @param ext type of certificate encoding
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 * @throws CMSException
	 */
	public CertificateEncapsulater(File certFile, CERT_TYPES ext)throws Exception{
		certs = new ArrayList<>();
		if(ext == CERT_TYPES.CER){
			loadCERFile(certFile);
		}else if(ext == CERT_TYPES.PEM){
			loadPEMFile(certFile);
		}else if(ext == CERT_TYPES.PFX){
			loadPFXFile(certFile);
		}else {
			loadP7BFile(certFile);
		}
	}
	
	/**
	 * Method for loading cer encoded certificate file
	 * @param certFile file containing certificate
	 * @throws CertificateException
	 * @throws IOException
	 */
	private void loadCERFile(File certFile) throws CertificateException, IOException{
		addCertsFromFile("X.509", certFile);
	}
	
	/**
	 * Method for loading PEM certificate file. Certificates must be bounded at the 
	 * beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by -----END CERTIFICATE-----.
	 * @param certFile
	 * @throws CertificateException
	 * @throws IOException 
	 */
	private void loadPEMFile(File certFile) throws CertificateException, IOException{
		addCertsFromFile("X.509", certFile);
	}
	
	/**
	 * method for loading P7B file
	 * @param certFile file containing P7B or P7C bundle
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 */
	private void loadP7BFile(File certFile) throws CertificateException, IOException, Base64DecodingException{
		addCertsFromFile("X.509", certFile);
	}
	
	/**
	 * Method for loading PFX file
	 * @param certFile
	 * @throws FileNotFoundException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws CertificateException
	 * @throws IOException
	 * @throws Base64DecodingException
	 */
	private void loadPFXFile(File certFile) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		PasswordPopup passwordPopup = new PasswordPopup();
		Optional<ButtonType> result = passwordPopup.showAndWait();
		if(result.isPresent() && result.get() == ButtonType.OK){
			getPasswordProtectedCerts(passwordPopup.getPassword(), certFile);
		}
		
	}
	
	/**
	 * Method for removing PKCS7 bounds
	 * @param certFile
	 * @return
	 * @throws IOException
	 */
	public static String removeBoundsP7B(File certFile) throws IOException{
		Scanner reader = new Scanner(new FileReader(certFile));
		StringBuilder cert = new StringBuilder();
		while(reader.hasNext()){
			String line = reader.nextLine();
		    if(!line.contains("PKCS7")){
		    	cert.append(line);
		    }
		}
		
		reader.close();
		
		return cert.toString();
	}

	/**
	 * @return the certs
	 */
	public List<X509Certificate> getCerts() {
		return certs;
	}

	/**
	 * @param certs the certs to set
	 */
	public void setCerts(List<X509Certificate> certs) {
		this.certs = certs;
	}
	
	public List<CertificateBean> getEncapulatedCerts(){
		List<CertificateBean> temp = new ArrayList<>();
		for(X509Certificate cert : certs)
			temp.add(new CertificateBean(cert));
		return temp;
	}
	
	private void loadCERFile(String certFile) throws CertificateException, IOException{
		addCertsFromString("X.509", certFile);
	}
			
	/**
	 * Method for loading base 64 pem string. Certificate/s must be bounded at the 
	 * beginning by -----BEGIN CERTIFICATE-----, and bounded at the end by -----END CERTIFICATE-----.
	 * @param certFile
	 * @throws CertificateException
	 * @throws IOException 
	 */
	private void loadPEMFile(String base64) throws CertificateException, IOException{
		String matchHeader = "-----.*";
		Pattern pattern = Pattern.compile(matchHeader);
		Matcher matcher = pattern.matcher(base64);
		while(matcher.find()){
			int start = matcher.start();
			matcher.find();
			int end = matcher.end();
			addCertFromPEMString(base64.substring(start, end));
		}		
	}
	
	private void loadP7BFile(String certFile) throws CertificateException, IOException, Base64DecodingException{
		addCertsFromString("X.509", certFile);
	}
	
	private void loadPFXFile(String certFile) throws CertificateException, IOException, XMLSecurityException, KeyStoreException, NoSuchAlgorithmException{
		loadPFXFile(new File(certFile));
	}
	
	private void addCertsFromFile(String instanceType, File certFile) throws CertificateException, IOException{
		CertificateFactory factory = CertificateFactory.getInstance(instanceType);
		Collection<? extends Certificate> col = 
				(Collection<? extends Certificate>)factory.generateCertificates(new FileInputStream(certFile));
		Iterator<? extends Certificate> itr = col.iterator();
		while(itr.hasNext()){
			certs.add((X509Certificate)itr.next());
		}
	}
	
	private void getPasswordProtectedCerts(String password, File certFile) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
        KeyStore p12 = KeyStore.getInstance("pkcs12");
        p12.load(new FileInputStream(certFile), password.toCharArray());
        Enumeration<String> e = p12.aliases();
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            X509Certificate cert = (X509Certificate) p12.getCertificate(alias);
            certs.add(cert);
        }
 
	}
	
	private void addCertsFromString(String instanceType, String certFile) throws CertificateException, IOException{
		CertificateFactory factory = CertificateFactory.getInstance(instanceType);
		@SuppressWarnings("unchecked")
		Collection<? extends Certificate> col = 
				(Collection<? extends Certificate>)factory.generateCertificate(
						new ByteArrayInputStream(certFile.getBytes()));
		Iterator<? extends Certificate> itr = col.iterator();
		while(itr.hasNext()){
			certs.add((X509Certificate)itr.next());
		}
	}
	
	private void addCertFromPEMString(String base64) throws CertificateException{
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		@SuppressWarnings("unchecked")
		X509Certificate cert = 
				(X509Certificate)factory.generateCertificate(
						new ByteArrayInputStream(base64.getBytes()));
		certs.add(cert);
		
	}
	
	

}
